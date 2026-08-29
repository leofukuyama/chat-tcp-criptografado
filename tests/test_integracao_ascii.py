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
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

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
    """

    def __enter__(self):
        self.processo = subprocess.Popen(
            [sys.executable, "-u", "server.py"],
            cwd=RAIZ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._esperar_porta_abrir()
        return self

    def _esperar_porta_abrir(self, limite=10.0):
        inicio = time.time()
        while time.time() - inicio < limite:
            if self.processo.poll() is not None:
                saida = self.processo.stdout.read().decode("utf-8", errors="replace")
                raise AssertionError(f"servidor morreu ao iniciar:\n{saida}")
            try:
                socket.create_connection((HOST, PORTA), timeout=0.3).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("servidor não abriu a porta a tempo")

    def log(self) -> str:
        """O que o servidor imprimiu no console até agora."""
        try:
            self.processo.stdin.write(b"/sair\n")
            self.processo.stdin.flush()
        except OSError:
            pass
        try:
            saida, _ = self.processo.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.processo.kill()
            saida, _ = self.processo.communicate()
        return saida.decode("utf-8", errors="replace")

    def __exit__(self, *_):
        if self.processo.poll() is None:
            try:
                self.processo.stdin.write(b"/sair\n")
                self.processo.stdin.flush()
            except OSError:
                pass
            try:
                self.processo.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.processo.kill()
                self.processo.communicate()
        return False


def conectar() -> socket.socket:
    sock = socket.create_connection((HOST, PORTA), timeout=5)
    sock.settimeout(ESPERA_SILENCIO)
    return sock


def ler(sock: socket.socket) -> bytes:
    """Bytes recebidos, ou b'' se nada chegou dentro do tempo de espera."""
    try:
        return sock.recv(1024)
    except socket.timeout:
        return b""


def drenar(sock: socket.socket) -> None:
    """Descarta avisos de sistema pendentes (ex: 'alguem entrou')."""
    while ler(sock):
        pass


# ============================================================
# TESTES
# ============================================================

def teste_mensagem_ascii_e_repassada_entre_clientes():
    with ServidorEmTeste():
        alice, bob = conectar(), conectar()
        drenar(alice)
        drenar(bob)

        alice.sendall(b"KMERWBK IAO")
        recebido = ler(bob)

        assert recebido == b"KMERWBK IAO", (
            f"Bob deveria ter recebido o payload cifrado, veio {recebido!r}"
        )
        alice.close()
        bob.close()


def teste_servidor_nao_repassa_bytes_nao_ascii():
    """O critério central: nem com cliente adulterado o conteúdo chega."""
    with ServidorEmTeste():
        alice, bob = conectar(), conectar()
        drenar(alice)
        drenar(bob)

        alice.sendall("cafe com acao \U0001F600".encode("utf-8"))
        recebido = ler(bob)

        assert recebido == b"", (
            f"Bob NAO deveria ter recebido nada, veio {recebido!r}"
        )
        alice.close()
        bob.close()


def teste_frame_bloqueado_nao_derruba_a_conexao():
    """Descartar o frame é suficiente; derrubar a sessão seria punir demais
    um cliente que mandou uma mensagem malformada."""
    with ServidorEmTeste():
        alice, bob = conectar(), conectar()
        drenar(alice)
        drenar(bob)

        alice.sendall("preco €50".encode("utf-8"))
        assert ler(bob) == b"", "o frame invalido nao deveria ter passado"

        alice.sendall(b"AINDA CONECTADO")
        recebido = ler(bob)

        assert recebido == b"AINDA CONECTADO", (
            "Alice deveria continuar na sala depois de um frame bloqueado, "
            f"mas a mensagem seguinte veio como {recebido!r}"
        )
        alice.close()
        bob.close()


def teste_todo_byte_alto_isolado_e_bloqueado():
    """Varre a fronteira: 0x7F ainda é ASCII e passa, 0x80 já não."""
    with ServidorEmTeste():
        alice, bob = conectar(), conectar()
        drenar(alice)
        drenar(bob)

        alice.sendall(bytes([0x7F]))
        assert ler(bob) == bytes([0x7F]), "0x7F (DEL) ainda e ASCII e deve passar"

        for byte_alto in [0x80, 0xC3, 0xE2, 0xFF]:
            alice.sendall(b"ok" + bytes([byte_alto]))
            recebido = ler(bob)
            assert recebido == b"", (
                f"o byte 0x{byte_alto:02X} deveria ter sido bloqueado, "
                f"mas o frame chegou como {recebido!r}"
            )
        alice.close()
        bob.close()


def teste_servidor_registra_o_bloqueio_no_log():
    with ServidorEmTeste() as servidor:
        alice, bob = conectar(), conectar()
        drenar(alice)
        drenar(bob)

        alice.sendall("acao".encode("utf-8").replace(b"a", b"\xc3\xa1", 1))
        ler(bob)
        alice.close()
        bob.close()
        log = servidor.log()

    assert "[BLOQUEADO]" in log, (
        f"o servidor deveria registrar o descarte no console. Log:\n{log}"
    )


def teste_nao_existe_handshake_de_apelido():
    """O servidor nao pode mais pedir NICK nem esperar resposta.

    Se ele pedisse, o primeiro byte recebido por um cliente novo seria
    'NICK' -- e um cliente que nao respondesse travaria o accept() dos
    demais, que era o comportamento antigo.
    """
    with ServidorEmTeste():
        alice = conectar()
        primeiro = ler(alice)

        assert b"NICK" not in primeiro, (
            f"o servidor ainda esta pedindo apelido: {primeiro!r}"
        )

        # Alice nunca respondeu nada. Se ainda houvesse handshake, o laco de
        # accept() estaria bloqueado em recv() e Bob nem conectaria.
        bob = conectar()
        aviso = ler(alice)

        assert aviso.startswith(b"SYS:"), (
            "Alice deveria receber o aviso de entrada de Bob mesmo sem ter "
            f"respondido nada, veio {aviso!r}"
        )
        alice.close()
        bob.close()


def teste_aviso_de_sistema_e_anonimo_e_ascii():
    with ServidorEmTeste():
        alice = conectar()
        bob = conectar()
        aviso = ler(alice)

        assert aviso == b"SYS:Alguem entrou no chat :D", (
            f"aviso de entrada inesperado: {aviso!r}"
        )

        bob.sendall(b"/sair")
        saida = ler(alice)

        assert saida == b"SYS:Alguem saiu do chat ;-;", (
            f"aviso de saida inesperado: {saida!r}"
        )
        alice.close()


# ============================================================
# RUNNER
# ============================================================

TESTES = [
    teste_mensagem_ascii_e_repassada_entre_clientes,
    teste_servidor_nao_repassa_bytes_nao_ascii,
    teste_frame_bloqueado_nao_derruba_a_conexao,
    teste_todo_byte_alto_isolado_e_bloqueado,
    teste_servidor_registra_o_bloqueio_no_log,
    teste_nao_existe_handshake_de_apelido,
    teste_aviso_de_sistema_e_anonimo_e_ascii,
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
