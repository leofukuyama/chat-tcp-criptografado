"""
Sessão Diffie-Hellman + César entre os DOIS participantes do chat.

Para CADA mensagem, o fluxo obrigatório do enunciado (passos 1 a 10) é:

    REMETENTE                         SERVIDOR            DESTINATÁRIO
    1. sorteia a (novo)
    2. A = g^a mod p
    3. ---- D "A <id> <tent> <A>" ---> imprime, repassa ---->
                                                        1. sorteia b (novo)
                                                        2. B = g^b mod p
                                                        4. s = A^b mod p
                                                        5. k = 1 + (s mod 25)
                                                        6. k == anterior?
                                                        7. imprime k
       <--- D "B <id> <B>" ---------- imprime, repassa ---
    4. s = B^a mod p
    5. k = 1 + (s mod 25)
    6. k == anterior? -> sim: volta ao passo 1 com um a NOVO
    7. imprime k
    8. C = César(texto, k)
       ---- M "<C>" -----------------> 9. imprime C, repassa ->
                                                       10. texto = César^-1(C, k)

Pela rede passam SOMENTE A e B (e o texto cifrado). Os valores a, b, s e k
existem só na memória de cada cliente; nenhum quadro os contém.

QUEM DECIDE QUE A CHAVE REPETIU (passo 6). Os dois lados calculam o mesmo k
e guardam o mesmo k anterior, então chegam à mesma conclusão sem conversar:
o destinatário responde B mesmo assim (o remetente precisa de B para
calcular k e perceber a repetição) e descarta a chave; o remetente começa
uma nova negociação com um valor privado novo. Isso só funciona se as
negociações forem ESTRITAMENTE SEQUENCIAIS, para que "a mensagem anterior"
seja a mesma nos dois lados. Daí as regras abaixo.

1. Fila local. Se o usuário digitar enquanto uma negociação está em
   andamento, a mensagem espera a vez.

2. Colisão. Se os dois usuários apertarem Enter quase juntos, cada lado
   manda o seu A antes de receber o A do outro. Cada negociação leva um
   identificador aleatório (<id>); vence o MENOR. Os dois lados comparam os
   mesmos dois ids, então concordam sobre quem vai primeiro sem trocar
   mais nenhuma mensagem. O perdedor descarta o próprio A (nunca chegou a
   calcular s com ele), atende o vencedor e recomeça depois, do passo 1.

3. Participantes. A sessão só negocia quando há DOIS participantes na
   sala; o servidor avisa a contagem com o quadro de controle
   "/participantes N" a cada entrada e saída. Sozinho, o usuário que digita
   recebe um aviso e a mensagem não é enviada (um A sem destinatário se
   perderia e a sessão ficaria esperando um B para sempre). Se o outro sai
   no meio de uma negociação, ela é cancelada. Quando alguém entra, começa
   uma conversa NOVA: o "k da mensagem anterior" do passo 6 vale entre
   ESSES dois clientes, então não é herdado da conversa com quem saiu.

Esta classe não conhece sockets: recebe uma função `enviar(tipo, texto)` e
uma função `exibir(linha)`. Assim os testes conseguem ligar duas sessões
diretamente, sem rede.
"""

import secrets
import threading
from collections import deque

import protocolo
from cifras import cesar
from cifras import diffie_hellman as dh

# Tamanho, em caracteres hexadecimais, do identificador de cada negociação.
TAMANHO_ID = 16


class ErroNegociacao(ValueError):
    """Quadro de negociação malformado ou com valor público inválido."""


class SessaoDH:
    def __init__(self, enviar, exibir, p: int = dh.P, g: int = dh.G):
        self._enviar = enviar
        self._exibir = exibir
        self.p = p
        self.g = g

        # Um único lock protege todo o estado: a thread de recebimento e a
        # thread que lê o teclado mexem nas mesmas estruturas.
        self._lock = threading.RLock()

        # Quantas pessoas há na sala, segundo o último "/participantes N"
        # do servidor. None = ainda não chegou nenhum aviso (tratado como
        # "sozinho": na dúvida, não negocia).
        self.participantes = None

        # Histórico de chaves aceitas, em ordem, desde que a sessão foi
        # criada (atravessa conversas). Usado pelos testes.
        self.chaves_aceitas = []

        self._nova_conversa()

    def _nova_conversa(self) -> None:
        """Zera tudo o que pertence à conversa entre ESTES dois clientes."""
        # k da mensagem imediatamente anterior entre estes dois clientes,
        # em QUALQUER sentido (passo 6).
        self.ultimo_k = None

        # Mensagens já entregues nesta conversa, nos dois sentidos. Como as
        # negociações são sequenciais, o número é o mesmo nos dois
        # terminais -- serve para casar as linhas na demonstração.
        self.mensagens_entregues = 0

        self._fila = deque()      # textos esperando para serem enviados
        self._saida = None        # negociação em que EU sou o remetente
        self._entrada = None      # chave aceita esperando o texto cifrado

    # ============================================================
    # ENTRADAS (chamadas por client.py)
    # ============================================================

    def _acompanhado(self) -> bool:
        return self.participantes is not None and self.participantes >= 2

    def definir_participantes(self, quantidade: int) -> None:
        """Quadro de controle "/participantes N" vindo do servidor."""
        with self._lock:
            estava_acompanhado = self._acompanhado()
            self.participantes = quantidade

            if self._acompanhado() and not estava_acompanhado:
                self._nova_conversa()
                self._exibir("")
                self._exibir(
                    "*** O outro participante está na sala: conversa iniciada. "
                    "Cada mensagem terá uma negociação Diffie-Hellman nova. ***"
                )
                return

            if not self._acompanhado():
                pendentes = len(self._fila)
                em_andamento = self._saida is not None or self._entrada is not None
                if estava_acompanhado:
                    self._exibir("")
                    self._exibir("*** O outro participante saiu da sala. ***")
                    if em_andamento:
                        self._exibir("   negociação em andamento cancelada")
                    if pendentes:
                        self._exibir(f"   {pendentes} mensagem(ns) NÃO enviada(s): não há ninguém para recebê-las")
                self._nova_conversa()
                self._exibir("*** Aguardando o outro participante para iniciar a conversa... ***")

    def enviar_texto(self, texto_claro: str) -> None:
        """O usuário digitou uma mensagem: entra na fila e, se der, começa."""
        with self._lock:
            if not self._acompanhado():
                self._exibir(
                    "   Mensagem NÃO enviada: não há ninguém na sala para recebê-la. "
                    "Aguarde o outro participante entrar."
                )
                return
            self._fila.append(texto_claro)
            if len(self._fila) > 1 or not self._ociosa():
                self._exibir(
                    f"   (mensagem na fila: aguardando a negociação em andamento -- "
                    f"{len(self._fila)} na fila)"
                )
            self._talvez_iniciar()

    def receber_negociacao(self, payload: str) -> None:
        """Quadro D vindo do outro cliente (via servidor)."""
        with self._lock:
            partes = payload.split(" ")
            try:
                if partes[0] == "A" and len(partes) == 4:
                    self._receber_A(partes[1], int(partes[2]), int(partes[3]))
                elif partes[0] == "B" and len(partes) == 3:
                    self._receber_B(partes[1], int(partes[2]))
                else:
                    raise ErroNegociacao(f"quadro de negociação malformado: {payload[:40]!r}")
            except ValueError as erro:
                self._exibir(f"*** negociação recusada: {erro} ***")

    def receber_mensagem(self, cifrado: str):
        """
        Quadro M vindo do outro cliente: passo 10. Devolve o texto
        original, ou None se não houver chave negociada para ele.
        """
        with self._lock:
            if self._entrada is None:
                self._exibir(
                    "*** texto cifrado recebido SEM negociação Diffie-Hellman -- "
                    "o outro participante escolheu a opção 9? Mensagem descartada. ***"
                )
                return None

            k = self._entrada["k"]
            numero = self._entrada["numero"]
            self._entrada = None

            texto = cesar.decifrar(cifrado, str(k))
            self.mensagens_entregues += 1
            self._exibir(f" [10] texto cifrado recebido:     {cifrado}")
            self._exibir(f"      decifrado com k = {k}")
            self._exibir(f"      TEXTO ORIGINAL (mensagem #{numero}): {texto}")
            self._exibir("")
            self._talvez_iniciar()
            return texto

    # ============================================================
    # LADO REMETENTE
    # ============================================================

    def _ociosa(self) -> bool:
        return self._saida is None and self._entrada is None

    def _talvez_iniciar(self) -> None:
        if self._fila and self._ociosa():
            self._iniciar_negociacao(tentativa=1)

    def _iniciar_negociacao(self, tentativa: int) -> None:
        numero = self.mensagens_entregues + 1
        id_neg = secrets.token_hex(TAMANHO_ID // 2)

        a = dh.gerar_privado(self.p)                    # passo 1
        A = dh.calcular_publico(a, self.p, self.g)      # passo 2

        self._saida = {"id": id_neg, "tentativa": tentativa, "a": a, "numero": numero}

        self._exibir("")
        self._exibir(
            f"=== MENSAGEM #{numero} | negociação {id_neg} | tentativa {tentativa} "
            f"| você é o REMETENTE ==="
        )
        self._exibir(f" [1] valor privado NOVO:   a = {dh.resumir(a)}   (fica só neste terminal)")
        self._exibir(f" [2] valor público:        A = g^a mod p = {dh.resumir(A)}")
        self._exibir(" [3] enviando A ao destinatário pelo servidor...")
        self._enviar(protocolo.TIPO_NEGOCIACAO, f"A {id_neg} {tentativa} {A}")

    def _receber_B(self, id_neg: str, B: int) -> None:
        if self._saida is None or self._saida["id"] != id_neg:
            # Resposta a uma negociação que já abandonamos (ex.: perdemos
            # uma colisão). Não há o que fazer com ela.
            return

        dh.validar_publico(B, self.p)
        a = self._saida["a"]
        tentativa = self._saida["tentativa"]
        numero = self._saida["numero"]

        s = dh.calcular_segredo(B, a, self.p)            # passo 4
        k = dh.chave_cesar(s)                            # passo 5

        self._exibir(f" [3] B recebido do destinatário: B = {dh.resumir(B)}")
        self._exibir(f" [4] segredo compartilhado:  s = B^a mod p = {dh.resumir(s)}")
        self._exibir(f" [5] chave de César:         k = 1 + (s mod 25) = 1 + {s % 25} = {k}")

        if self._chave_repetida(k):                      # passo 6
            # Nova negociação, com valor privado novo. a, A e s desta
            # tentativa são simplesmente esquecidos.
            self._saida = None
            self._iniciar_negociacao(tentativa + 1)
            return

        self._aceitar(k)
        texto = self._fila.popleft()
        cifrado = cesar.cifrar(texto, str(k))            # passo 8
        self._saida = None

        self._exibir(f" [7] CHAVE DESTA MENSAGEM:   k = {k}")
        self._exibir(f" [8] texto original:         {texto}")
        self._exibir(f"     cifrado com César (k={k}): {cifrado}   -> enviado ao servidor")
        self._exibir("")
        self.mensagens_entregues += 1
        self._enviar(protocolo.TIPO_MENSAGEM, cifrado)
        self._talvez_iniciar()

    # ============================================================
    # LADO DESTINATÁRIO
    # ============================================================

    def _receber_A(self, id_neg: str, tentativa: int, A: int) -> None:
        if self._saida is not None:
            # COLISÃO: nós também estamos esperando um B. Vence o menor id.
            meu_id = self._saida["id"]
            if id_neg > meu_id:
                self._exibir(
                    f"   (colisão: o outro participante também começou a enviar; "
                    f"a negociação {meu_id} vai primeiro e a dele recomeça depois)"
                )
                return
            self._exibir(
                f"   (colisão: o outro participante também começou a enviar; "
                f"a negociação dele, {id_neg}, vai primeiro -- a sua recomeça depois)"
            )
            self._saida = None

        dh.validar_publico(A, self.p)
        numero = self.mensagens_entregues + 1

        b = dh.gerar_privado(self.p)                     # passo 1
        B = dh.calcular_publico(b, self.p, self.g)       # passo 2
        s = dh.calcular_segredo(A, b, self.p)            # passo 4
        k = dh.chave_cesar(s)                            # passo 5

        self._exibir("")
        self._exibir(
            f"=== MENSAGEM #{numero} | negociação {id_neg} | tentativa {tentativa} "
            f"| você é o DESTINATÁRIO ==="
        )
        self._exibir(f" [3] A recebido do remetente: A = {dh.resumir(A)}")
        self._exibir(f" [1] valor privado NOVO:   b = {dh.resumir(b)}   (fica só neste terminal)")
        self._exibir(f" [2] valor público:        B = g^b mod p = {dh.resumir(B)}")
        self._exibir(f" [4] segredo compartilhado:  s = A^b mod p = {dh.resumir(s)}")
        self._exibir(f" [5] chave de César:         k = 1 + (s mod 25) = 1 + {s % 25} = {k}")

        if self._chave_repetida(k):                      # passo 6
            self._entrada = None
            self._exibir(" [3] enviando B ao remetente pelo servidor (ele também precisa ver a repetição)...")
            self._enviar(protocolo.TIPO_NEGOCIACAO, f"B {id_neg} {B}")
            return

        self._aceitar(k)
        self._entrada = {"k": k, "numero": numero}
        self._exibir(f" [7] CHAVE DESTA MENSAGEM:   k = {k}")
        self._exibir(" [3] enviando B ao remetente pelo servidor... aguardando o texto cifrado")
        self._enviar(protocolo.TIPO_NEGOCIACAO, f"B {id_neg} {B}")

    # ============================================================
    # PASSO 6, COMUM AOS DOIS LADOS
    # ============================================================

    def _chave_repetida(self, k: int) -> bool:
        if self.ultimo_k is not None and k == self.ultimo_k:
            self._exibir(
                f" [6] verificação: k = {k} é IGUAL ao da mensagem anterior "
                f"-> descartada, nova negociação com valores privados novos"
            )
            return True
        anterior = "nenhuma (primeira mensagem)" if self.ultimo_k is None else f"k = {self.ultimo_k}"
        self._exibir(f" [6] verificação: mensagem anterior usou {anterior} -> chave aceita")
        return False

    def _aceitar(self, k: int) -> None:
        self.ultimo_k = k
        self.chaves_aceitas.append(k)
