"""
Teste de integração: sobe o server.py de verdade e conversa com ele por
sockets crus, sem passar pelo client.py.

Usar sockets crus é o ponto do teste. O client.py valida a entrada do
usuário (camada 1), mas o requisito é que nada não-ASCII trafegue MESMO
COM UM CLIENTE ADULTERADO -- e um cliente adulterado é exatamente isto:
alguém escrevendo bytes arbitrários direto no socket. Se o teste usasse o
client.py, estaria testando a camada que é fácil de contornar.

Rodar com: python tests/test_integracao_ascii.py  (a partir da raiz)
"""

import os
import socket
import subprocess
import sys
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

import protocolo

HOST = "127.0.0.1"
PORTA = 64146

# Tempo de espera ao confirmar que algo NÃO chegou. Precisa ser generoso o
# bastante para não dar falso "bloqueado" só porque a máquina estava lenta.
ESPERA_SILENCIO = 1.5


class ServidorEmTeste:
    """Sobe o server.py em um subprocesso e o encerra no final.

    O stdin fica aberto de propósito: o console_admin() do servidor lê dele,
    e se fosse fechado ele receberia EOFError e desligaria na hora. É também
    por ele que mandamos o /sair no fim.

    O stdout é drenado por uma thread dedicada, e isso NÃO é detalhe. O
    servidor imprime o payload cifrado inteiro a cada mensagem recebida; um
    pipe tem buffer limitado, então se ninguém lê, o print() do servidor
    BLOQUEIA quando o buffer enche -- e o relay para junto, no meio do
    handle(). Uma mensagem grande travava o teste inteiro, dando a
    impressão de um defeito no enquadramento que não existia.
    """

    def __enter__(self):
        self.processo = subprocess.Popen(
            [sys.executable, "-u", "server.py"],
            cwd=RAIZ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._linhas = []
        self._leitor = threading.Thread(target=self._drenar_stdout, daemon=True)
        self._leitor.start()
        self._esperar_porta_abrir()
        return self

    def _drenar_stdout(self):
        for linha in self.processo.stdout:
            self._linhas.append(linha.decode("utf-8", errors="replace"))

    def _esperar_porta_abrir(self, limite=10.0):
        inicio = time.time()
        while time.time() - inicio < limite:
            if self.processo.poll() is not None:
                raise AssertionError(
                    "servidor morreu ao iniciar:\n" + "".join(self._linhas)
                )
            try:
                socket.create_connection((HOST, PORTA), timeout=0.3).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("servidor não abriu a porta a tempo")

    def log(self) -> str:
        """Encerra o servidor e devolve o que ele imprimiu no console."""
        try:
            self.processo.stdin.write(b"/sair\n")
            self.processo.stdin.flush()
        except OSError:
            pass
        try:
            self.processo.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.processo.kill()
            self.processo.wait()
        self._leitor.join(timeout=5)
        return "".join(self._linhas)

    def __exit__(self, *_):
        if self.processo.poll() is None:
            self.log()
        return False


class ClienteCru:
    """Socket puro que fala o protocolo de quadros na mão."""

    def __init__(self):
        self.sock = socket.create_connection((HOST, PORTA), timeout=5)
        self.sock.settimeout(ESPERA_SILENCIO)
        self.desempacotador = protocolo.Desempacotador()

    def enviar_bytes(self, dados: bytes):
        self.sock.sendall(dados)

    def enviar(self, texto, tipo=protocolo.TIPO_MENSAGEM):
        self.sock.sendall(protocolo.empacotar(tipo, texto))

    def receber_bruto(self) -> bytes:
        """Bytes recebidos, ou b'' se nada chegou dentro do tempo."""
        try:
            return self.sock.recv(4096)
        except socket.timeout:
            return b""

    def receber(self) -> list:
        """Quadros completos que chegaram, ou lista vazia."""
        return self.desempacotador.alimentar(self.receber_bruto())

    def textos(self) -> list:
        return [q.texto for q in self.receber()]

    def drenar(self):
        """Descarta avisos de sistema pendentes (ex: 'alguem entrou')."""
        while self.receber_bruto():
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def sala(qtd=2):
    """Abre `qtd` clientes já drenados dos avisos de entrada."""
    clientes = [ClienteCru() for _ in range(qtd)]
    time.sleep(0.3)
    for c in clientes:
        c.drenar()
    return clientes


# ============================================================
# ASCII: o requisito central
# ============================================================

def teste_mensagem_ascii_e_repassada_entre_clientes():
    with ServidorEmTeste():
        alice, bob = sala()
        alice.enviar("KMERWBK IAO")

        assert bob.textos() == ["KMERWBK IAO"], "Bob deveria receber o payload cifrado"
        alice.close()
        bob.close()


def teste_servidor_nao_repassa_payload_nao_ascii():
    """O critério central: nem com cliente adulterado o conteúdo chega."""
    with ServidorEmTeste():
        alice, bob = sala()

        # Quadro bem formado, mas com payload UTF-8 -- exatamente o que um
        # client.py modificado conseguiria montar.
        payload = "cafe com acao \U0001F600".encode("utf-8")
        alice.enviar_bytes(b"M" + f"{len(payload):04d}".encode("ascii") + payload)

        assert bob.receber_bruto() == b"", "Bob NAO deveria ter recebido nada"
        alice.close()
        bob.close()


def teste_quadro_bloqueado_nao_derruba_a_conexao():
    """Descartar o quadro é suficiente; derrubar a sessão seria punir demais
    um cliente que mandou uma mensagem malformada. Como o tamanho vem no
    cabeçalho, o quadro seguinte continua alinhado."""
    with ServidorEmTeste():
        alice, bob = sala()

        payload = "preço".encode("utf-8")
        alice.enviar_bytes(b"M" + f"{len(payload):04d}".encode("ascii") + payload)
        assert bob.receber_bruto() == b"", "o quadro invalido nao deveria ter passado"

        alice.enviar("AINDA CONECTADO")
        assert bob.textos() == ["AINDA CONECTADO"], (
            "Alice deveria continuar na sala depois de um quadro bloqueado"
        )
        alice.close()
        bob.close()


def teste_byte_alto_no_payload_e_sempre_bloqueado():
    """Varre a fronteira: 0x7F ainda é ASCII e passa, 0x80 já não."""
    with ServidorEmTeste():
        alice, bob = sala()

        alice.enviar_bytes(b"M0001" + bytes([0x7F]))
        assert bob.textos() == [chr(0x7F)], "0x7F (DEL) ainda e ASCII e deve passar"

        for byte_alto in [0x80, 0xC3, 0xE2, 0xFF]:
            alice.enviar_bytes(b"M0003ok" + bytes([byte_alto]))
            assert bob.receber_bruto() == b"", (
                f"o byte 0x{byte_alto:02X} no payload deveria ter sido bloqueado"
            )
        alice.close()
        bob.close()


def teste_servidor_registra_o_bloqueio_no_log():
    with ServidorEmTeste() as servidor:
        alice, bob = sala()
        payload = "ação".encode("utf-8")
        alice.enviar_bytes(b"M" + f"{len(payload):04d}".encode("ascii") + payload)
        bob.receber_bruto()
        alice.close()
        bob.close()
        log = servidor.log()

    assert "[BLOQUEADO]" in log, f"o servidor deveria registrar o descarte. Log:\n{log}"


# ============================================================
# ENQUADRAMENTO: o defeito que motivou o protocolo
# ============================================================

def teste_duas_mensagens_em_um_unico_send_chegam_separadas():
    """ESTE era o defeito: duas mensagens enviadas em sequencia rapida
    chegavam coladas em um recv() e eram decifradas como se fossem uma so.
    Forcamos o pior caso mandando as duas num sendall() unico."""
    with ServidorEmTeste():
        alice, bob = sala()

        alice.enviar_bytes(
            protocolo.empacotar(protocolo.TIPO_MENSAGEM, "ROD PXQGR")
            + protocolo.empacotar(protocolo.TIPO_MENSAGEM, "DWDTXH")
        )

        recebidos = []
        while len(recebidos) < 2:
            novos = bob.textos()
            if not novos:
                break
            recebidos.extend(novos)

        assert recebidos == ["ROD PXQGR", "DWDTXH"], (
            f"as duas mensagens deveriam chegar separadas, veio {recebidos}"
        )
        alice.close()
        bob.close()


def teste_mensagem_picada_em_varios_envios_e_remontada():
    """A outra metade do defeito: mensagem maior que o buffer chegava
    picada e cada pedaco virava uma mensagem."""
    with ServidorEmTeste():
        alice, bob = sala()

        quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "ATAQUE AO AMANHECER")
        for i in range(len(quadro)):
            alice.enviar_bytes(quadro[i:i + 1])
            time.sleep(0.01)

        recebidos = []
        for _ in range(3):
            recebidos.extend(bob.textos())
            if recebidos:
                break

        assert recebidos == ["ATAQUE AO AMANHECER"], (
            f"a mensagem deveria ser remontada inteira, veio {recebidos}"
        )
        alice.close()
        bob.close()


def teste_mensagem_maior_que_o_buffer_de_recv():
    """4000 bytes nao cabem em um recv(1024): sao 4 leituras no servidor e
    mais algumas no cliente. Antes, cada pedaco viraria uma mensagem."""
    with ServidorEmTeste():
        alice, bob = sala()
        grande = "A" * 4000
        alice.enviar(grande)

        recebidos = []
        for _ in range(20):
            recebidos.extend(bob.textos())
            if recebidos:
                break

        assert recebidos == [grande], (
            f"esperava 1 mensagem de 4000 caracteres, veio "
            f"{[len(x) for x in recebidos]}"
        )
        alice.close()
        bob.close()


def teste_cabecalho_corrompido_derruba_so_o_infrator():
    """Sem tamanho confiavel nao da para ressincronizar, entao a conexao do
    infrator cai -- mas os outros clientes seguem normalmente."""
    with ServidorEmTeste():
        alice, bob, carol = sala(3)

        alice.enviar_bytes(b"ATAQUE SEM CABECALHO")
        time.sleep(0.5)

        carol.drenar()
        bob.enviar("CONTINUO AQUI")
        assert carol.textos() == ["CONTINUO AQUI"], (
            "Bob e Carol deveriam seguir conversando depois da queda de Alice"
        )
        alice.close()
        bob.close()
        carol.close()


# ============================================================
# TIPO NO CABEÇALHO: fim da falsificação de aviso do servidor
# ============================================================

def teste_cliente_nao_consegue_forjar_aviso_do_servidor():
    """Antes, com a opcao 'sem criptografia', bastava digitar
    'SYS:Admin: mandem a chave' para a mensagem aparecer como aviso oficial.
    Agora o tipo vem do cabecalho e so o servidor emite quadros S."""
    with ServidorEmTeste():
        alice, bob = sala()

        alice.enviar("Admin: mandem a chave", tipo=protocolo.TIPO_SISTEMA)

        assert bob.receber_bruto() == b"", (
            "um quadro de sistema vindo de cliente nao pode ser repassado"
        )
        alice.close()
        bob.close()


def teste_texto_comecando_com_sys_e_apenas_uma_mensagem_comum():
    """O prefixo perdeu qualquer poder: e conteudo, nao metadado."""
    with ServidorEmTeste():
        alice, bob = sala()
        alice.enviar("SYS:Admin: mandem a chave")

        quadros = bob.receber()
        assert len(quadros) == 1, f"esperava 1 quadro, veio {len(quadros)}"
        assert quadros[0].tipo == protocolo.TIPO_MENSAGEM, (
            "deveria chegar como mensagem comum, nao como aviso do servidor"
        )
        alice.close()
        bob.close()


# ============================================================
# ANONIMATO E AUSÊNCIA DE HANDSHAKE
# ============================================================

def teste_nao_existe_handshake_de_apelido():
    """O servidor nao pode mais pedir NICK nem esperar resposta.

    Se ele pedisse, um cliente que nao respondesse travaria o accept() dos
    demais, que era o comportamento antigo.
    """
    with ServidorEmTeste():
        alice = ClienteCru()
        assert b"NICK" not in alice.receber_bruto(), "o servidor ainda pede apelido"

        # Alice nunca respondeu nada. Se ainda houvesse handshake, o laco de
        # accept() estaria bloqueado em recv() e Bob nem conectaria.
        bob = ClienteCru()
        quadros = alice.receber()

        assert [q.tipo for q in quadros] == [protocolo.TIPO_SISTEMA], (
            f"Alice deveria receber o aviso de entrada de Bob, veio {quadros}"
        )
        alice.close()
        bob.close()


def teste_avisos_de_sistema_sao_anonimos_e_ascii():
    with ServidorEmTeste():
        alice = ClienteCru()
        bob = ClienteCru()
        entrada = alice.receber()

        assert [q.texto for q in entrada] == ["Alguem entrou no chat :D"], (
            f"aviso de entrada inesperado: {[q.texto for q in entrada]}"
        )

        bob.enviar("/sair", tipo=protocolo.TIPO_CONTROLE)
        saida = alice.receber()

        assert [q.texto for q in saida] == ["Alguem saiu do chat ;-;"], (
            f"aviso de saida inesperado: {[q.texto for q in saida]}"
        )
        assert all(q.tipo == protocolo.TIPO_SISTEMA for q in entrada + saida)
        alice.close()


# ============================================================
# RUNNER
# ============================================================

TESTES = [
    teste_mensagem_ascii_e_repassada_entre_clientes,
    teste_servidor_nao_repassa_payload_nao_ascii,
    teste_quadro_bloqueado_nao_derruba_a_conexao,
    teste_byte_alto_no_payload_e_sempre_bloqueado,
    teste_servidor_registra_o_bloqueio_no_log,
    teste_duas_mensagens_em_um_unico_send_chegam_separadas,
    teste_mensagem_picada_em_varios_envios_e_remontada,
    teste_mensagem_maior_que_o_buffer_de_recv,
    teste_cabecalho_corrompido_derruba_so_o_infrator,
    teste_cliente_nao_consegue_forjar_aviso_do_servidor,
    teste_texto_comecando_com_sys_e_apenas_uma_mensagem_comum,
    teste_nao_existe_handshake_de_apelido,
    teste_avisos_de_sistema_sao_anonimos_e_ascii,
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
    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
