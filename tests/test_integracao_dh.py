"""
Integração da opção 9 (Diffie-Hellman + César) com o server.py REAL.

Sobe o servidor em subprocesso (mesmo harness de test_integracao_ascii.py)
e liga duas SessaoDH a sockets de verdade. Confere, pelo log do servidor,
o que o enunciado pede que apareça no terminal dele.

Rodar com: python tests/test_integracao_dh.py  (a partir da raiz)
"""

import os
import socket
import sys
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
sys.path.insert(0, os.path.join(RAIZ, "tests"))

import protocolo
import sessao_dh
from cifras import diffie_hellman as dh
from test_integracao_ascii import HOST, PORTA, ClienteCru, ServidorEmTeste


class ClienteDH:
    """Socket real + SessaoDH + thread de recebimento (o que client.py faz)."""

    def __init__(self, nome):
        self.nome = nome
        self.sock = socket.create_connection((HOST, PORTA), timeout=5)
        self.sock.settimeout(None)
        self.tela = []
        self.recebidas = []
        self.sistema = []
        self.sessao = sessao_dh.SessaoDH(self._enviar, self.tela.append)
        self._thread = threading.Thread(target=self._receber, daemon=True)
        self._thread.start()

    def _enviar(self, tipo, texto):
        self.sock.sendall(protocolo.empacotar(tipo, texto))

    def _receber(self):
        d = protocolo.Desempacotador()
        while True:
            try:
                dados = self.sock.recv(4096)
            except OSError:
                return
            if not dados:
                return
            for q in d.alimentar(dados):
                if q.tipo == protocolo.TIPO_NEGOCIACAO:
                    self.sessao.receber_negociacao(q.texto)
                elif q.tipo == protocolo.TIPO_MENSAGEM:
                    self.recebidas.append(self.sessao.receber_mensagem(q.texto))
                elif q.tipo == protocolo.TIPO_SISTEMA:
                    self.sistema.append(q.texto)
                elif q.tipo == protocolo.TIPO_CONTROLE and q.texto.startswith("/participantes "):
                    # O mesmo que client.py faz com o aviso do servidor.
                    self.sessao.definir_participantes(int(q.texto.split(" ")[1]))

    def esperar_participantes(self, quantidade, limite=5.0):
        inicio = time.time()
        while self.sessao.participantes != quantidade:
            if time.time() - inicio > limite:
                raise AssertionError(
                    f"{self.nome}: esperava {quantidade} participantes, "
                    f"está com {self.sessao.participantes}"
                )
            time.sleep(0.05)

    def esperar(self, quantidade, limite=20.0):
        inicio = time.time()
        while len(self.recebidas) < quantidade:
            if time.time() - inicio > limite:
                raise AssertionError(f"{self.nome} recebeu só {len(self.recebidas)} de {quantidade}")
            time.sleep(0.05)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def teste_cinco_mensagens_pelo_servidor_real():
    textos = ["OLA BOB", "OLA BOB", "ATACAR BASE NORTE.", "AS 10H", "CONFIRMA?"]
    with ServidorEmTeste() as servidor:
        alice, bob = ClienteDH("alice"), ClienteDH("bob")
        alice.esperar_participantes(2)
        bob.esperar_participantes(2)
        for i, t in enumerate(textos, start=1):
            alice.sessao.enviar_texto(t)
            bob.esperar(i)
        alice.close()
        bob.close()
        log = servidor.log()

    assert bob.recebidas == textos, f"Bob recuperou {bob.recebidas}"
    ks = alice.sessao.chaves_aceitas
    assert ks == bob.sessao.chaves_aceitas, "mesma chave nos dois clientes"
    assert all(ks[i] != ks[i + 1] for i in range(len(ks) - 1)), f"chaves consecutivas iguais: {ks}"

    cifrados_no_servidor = [l.split("] ", 1)[1].strip() for l in log.splitlines() if l.startswith("[CIFRADO recebido]")]
    assert len(cifrados_no_servidor) == 5, f"servidor deveria imprimir 5 textos cifrados:\n{log}"
    for texto, cifrado in zip(textos, cifrados_no_servidor):
        assert cifrado != texto, "o servidor viu texto claro"
    negociacoes = [l for l in log.splitlines() if l.startswith("[DH repassado]")]
    assert len([l for l in negociacoes if "] A " in l or l.split()[2] == "A"]) >= 5, (
        "servidor deveria repassar ao menos um A por mensagem"
    )


def teste_servidor_nao_importa_nada_de_diffie_hellman():
    codigo = open(os.path.join(RAIZ, "server.py"), encoding="utf-8").read()
    assert "diffie_hellman" not in codigo and "sessao_dh" not in codigo and "cifras" not in codigo


def teste_terceira_conexao_e_recusada():
    with ServidorEmTeste() as servidor:
        alice, bob = ClienteCru(), ClienteCru()
        time.sleep(0.3)
        carol = ClienteCru()
        quadros = carol.receber()
        assert [q.texto for q in quadros] == ["Sala cheia: este chat aceita somente 2 participantes."]
        assert carol.receber_bruto() == b"", "a conexão da terceira pessoa deveria ser fechada"
        alice.drenar()
        bob.drenar()
        alice.enviar("AINDA FUNCIONA")
        assert bob.textos() == ["AINDA FUNCIONA"], "os dois de dentro seguem conversando"
        for c in (alice, bob, carol):
            c.close()
        assert "[RECUSADO]" in servidor.log()


def teste_sozinho_nao_envia_e_a_conversa_comeca_quando_o_outro_entra():
    with ServidorEmTeste() as servidor:
        alice = ClienteDH("alice")
        alice.esperar_participantes(1)
        alice.sessao.enviar_texto("TEM ALGUEM?")
        time.sleep(0.5)
        assert any("não há ninguém na sala" in l for l in alice.tela)

        bob = ClienteDH("bob")
        alice.esperar_participantes(2)
        bob.esperar_participantes(2)
        alice.sessao.enviar_texto("AGORA SIM")
        bob.esperar(1)
        alice.close()
        bob.close()
        log = servidor.log()

    assert bob.recebidas == ["AGORA SIM"], "a mensagem recusada não pode chegar depois"
    assert log.count("[CIFRADO recebido]") == 1
    primeiro_dh = log.index("[DH repassado]")
    assert log.index("Conectado com", log.index("Conectado com") + 1) < primeiro_dh, (
        "nenhuma negociação pode começar antes de o segundo participante entrar"
    )


def teste_saida_no_meio_da_negociacao_nao_trava_quem_ficou():
    with ServidorEmTeste():
        alice = ClienteDH("alice")
        bob_cru = ClienteCru()          # recebe o A e sai sem responder
        alice.esperar_participantes(2)
        bob_cru.drenar()
        alice.sessao.enviar_texto("PRIMEIRA")
        quadros = bob_cru.receber()
        assert any(q.tipo == protocolo.TIPO_NEGOCIACAO for q in quadros), "Bob deveria receber o A"
        bob_cru.close()

        alice.esperar_participantes(1)
        assert any("negociação em andamento cancelada" in l for l in alice.tela)

        bob = ClienteDH("bob")
        alice.esperar_participantes(2)
        bob.esperar_participantes(2)
        alice.sessao.enviar_texto("DEPOIS")
        bob.esperar(1)
        assert bob.recebidas == ["DEPOIS"], "a sessão da Alice ficou travada"
        alice.close()
        bob.close()


TESTES = [
    teste_cinco_mensagens_pelo_servidor_real,
    teste_sozinho_nao_envia_e_a_conversa_comeca_quando_o_outro_entra,
    teste_saida_no_meio_da_negociacao_nao_trava_quem_ficou,
    teste_servidor_nao_importa_nada_de_diffie_hellman,
    teste_terceira_conexao_e_recusada,
]


def rodar_todos():
    falhas = 0
    for teste in TESTES:
        try:
            teste()
            print(f"[OK]    {teste.__name__}")
        except AssertionError as e:
            falhas += 1
            print(f"[FALHA] {teste.__name__} -- {e}")
    print(f"\n{len(TESTES) - falhas}/{len(TESTES)} testes passaram.")
    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
