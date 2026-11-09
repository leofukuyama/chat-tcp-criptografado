"""
Demonstração da opção 9 (Diffie-Hellman + César) com os programas REAIS.

Sobe o server.py e dois client.py (Alice e Bob) como processos separados,
escolhe a opção 9 nos dois, digita as mensagens no terminal da Alice (e uma
resposta no do Bob) e captura o que cada um dos três terminais imprimiu.

Mostra, para cada mensagem, o que a entrega do projeto pede:
  - uma nova negociação para cada mensagem;
  - a mesma chave nos dois clientes;
  - chaves diferentes entre mensagens consecutivas;
  - o texto cifrado no terminal do servidor;
  - o texto original recuperado no cliente destinatário.

Rodar a partir da raiz do projeto (a porta 64146 precisa estar livre):
    python scripts/demonstracao_dh.py

Os três terminais completos são gravados em docs/demonstracao-dh.txt.
"""

import os
import re
import socket
import subprocess
import sys
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAIDA = os.path.join(RAIZ, "docs", "demonstracao-dh.txt")

# (quem digita, texto). As cinco primeiras são consecutivas, da Alice para o
# Bob, e incluem o MESMO texto duas vezes: mesmo assim cada uma tem sua
# própria negociação. A última é a resposta do Bob, para mostrar o sentido
# contrário e que a regra da "mensagem anterior" vale para a conversa toda.
MENSAGENS = [
    ("alice", "Ola Bob"),
    ("alice", "Ola Bob"),
    ("alice", "Atacar base norte."),
    ("alice", "As 10h, sem falta"),
    ("alice", "Confirma?"),
    ("bob", "Confirmado, Alice!"),
]

AMBIENTE = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")


class Processo:
    def __init__(self, nome, script):
        self.nome = nome
        self.proc = subprocess.Popen(
            [sys.executable, "-u", script],
            cwd=RAIZ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=AMBIENTE,
        )
        self._partes = []
        threading.Thread(target=self._drenar, daemon=True).start()

    def _drenar(self):
        while True:
            pedaco = self.proc.stdout.read1(4096)
            if not pedaco:
                return
            self._partes.append(pedaco)

    def texto(self) -> str:
        """
        O que ficou visível no terminal. Um "\\r" volta ao começo da linha e
        o que vem depois a sobrescreve (é assim que o cliente redesenha o
        prompt " > "), então de cada linha fica só o último trecho.
        """
        bruto = b"".join(self._partes).decode("utf-8", errors="replace")
        linhas = []
        for linha in bruto.split("\n"):
            trechos = [t for t in linha.split("\r") if t.strip()]
            linhas.append(trechos[-1] if trechos else "")
        return "\n".join(linhas)

    def digitar(self, linha):
        self.proc.stdin.write((linha + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def esperar(self, trecho, limite=30.0):
        inicio = time.time()
        while trecho not in self.texto():
            if self.proc.poll() is not None or time.time() - inicio > limite:
                raise RuntimeError(f"{self.nome}: não apareceu {trecho!r}\n{self.texto()}")
            time.sleep(0.05)

    def encerrar(self):
        try:
            self.digitar("/sair")
            self.proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait()




def limpar(texto):
    """Tira as linhas que são só o prompt ' > ' redesenhado."""
    linhas = []
    for l in texto.splitlines():
        while l.startswith(" > "):
            l = l[3:].lstrip(" ") if l[3:4] == " " and l[4:5] in "[ " else l[3:]
            l = (" " + l) if l.startswith("[") else l
        if l.strip() not in (">", ""):
            linhas.append(l)
    return "\n".join(linhas)


def resumo(alice, bob, servidor):
    """Tabela final: uma linha por mensagem, extraída dos três terminais."""
    def blocos(texto):
        atual, por_numero = None, {}
        for linha in texto.splitlines():
            m = re.search(r"=== MENSAGEM #(\d+) \| negociação (\w+) \| tentativa (\d+)", linha)
            if m:
                atual = int(m.group(1))
                info = por_numero.setdefault(atual, {"negociacoes": [], "k": None, "original": None})
                info["negociacoes"].append(m.group(2))
            m = re.search(r"CHAVE DESTA MENSAGEM:\s+k = (\d+)", linha)
            if m and atual:
                por_numero[atual]["k"] = int(m.group(1))
            m = re.search(r"TEXTO ORIGINAL \(mensagem #(\d+)\): (.*)", linha)
            if m:
                por_numero.setdefault(int(m.group(1)), {"negociacoes": [], "k": None})["original"] = m.group(2)
        return por_numero

    ba, bb = blocos(alice), blocos(bob)
    cifrados = [l.split("]", 1)[1].strip() for l in servidor.splitlines() if l.startswith("[CIFRADO recebido]")]
    a_repassados = [l for l in servidor.splitlines() if re.match(r"\[DH repassado\]\s+A ", l)]

    linhas = [
        "",
        "RESUMO (extraído dos três terminais)",
        f"{'#':>2}  {'de':<6} {'negociações':>11}  {'k Alice':>7}  {'k Bob':>5}  {'cifrado no SERVIDOR':<22}  original recuperado no destinatário",
    ]
    anterior = None
    for n, (quem, texto) in enumerate(MENSAGENS, start=1):
        destino = bb if quem == "alice" else ba
        ka, kb = ba.get(n, {}).get("k"), bb.get(n, {}).get("k")
        negs = len(ba.get(n, {}).get("negociacoes", []))
        cif = cifrados[n - 1] if n - 1 < len(cifrados) else "?"
        original = destino.get(n, {}).get("original")
        linhas.append(f"{n:>2}  {quem:<6} {negs:>11}  {ka!s:>7}  {kb!s:>5}  {cif:<22}  {original}")
        assert ka == kb, f"mensagem {n}: chaves diferentes nos dois clientes"
        assert ka != anterior, f"mensagem {n}: chave igual à da mensagem anterior"
        assert original is not None and original == texto.upper(), f"mensagem {n}: texto não recuperado"
        assert cif != "?", f"mensagem {n}: o texto cifrado não apareceu no terminal do servidor"
        assert cif != texto.upper(), f"mensagem {n}: o servidor viu o texto em claro"
        anterior = ka
    assert len(cifrados) == len(MENSAGENS), (
        f"o servidor imprimiu {len(cifrados)} textos cifrados para {len(MENSAGENS)} mensagens"
    )
    assert len(a_repassados) >= len(MENSAGENS), (
        f"o servidor repassou {len(a_repassados)} valores A para {len(MENSAGENS)} mensagens: "
        "cada mensagem precisa de uma negociação própria"
    )
    linhas.append("")
    linhas.append(f"Negociações (valores A) que passaram pelo servidor: {len(a_repassados)} "
                  f"para {len(MENSAGENS)} mensagens.")
    linhas.append("Conferido: mesma chave nos dois clientes, chaves consecutivas diferentes,")
    linhas.append("texto cifrado no servidor e texto original recuperado no destinatário.")
    return "\n".join(linhas)


def porta_ocupada() -> bool:
    """Já existe algum servidor escutando na porta do chat?"""
    try:
        socket.create_connection(("127.0.0.1", 64146), timeout=0.5).close()
        return True
    except OSError:
        return False


def main():
    # No Windows, o SO_REUSEADDR do server.py deixa um SEGUNDO servidor abrir
    # a porta 64146 sem erro, e os clientes acabam conectados ao servidor
    # antigo: a conversa funciona, mas o terminal capturado aqui fica vazio.
    if porta_ocupada():
        print("Já existe um servidor rodando na porta 64146 (outro terminal com server.py?).")
        print("Encerre-o (digite /sair no terminal dele) e rode a demonstração de novo.")
        sys.exit(1)

    servidor = Processo("servidor", "server.py")
    try:
        servidor.esperar("Servidor está online")
        time.sleep(0.3)
        alice = Processo("alice", "client.py")
        servidor.esperar("Conectado com")
        bob = Processo("bob", "client.py")
        inicio = time.time()
        while servidor.texto().count("Conectado com") < 2:
            if time.time() - inicio > 10:
                raise RuntimeError(
                    "os clientes não se conectaram ao servidor desta demonstração "
                    "(há outro servidor na porta 64146?)"
                )
            time.sleep(0.05)
        clientes = {"alice": alice, "bob": bob}

        print("Escolhendo a opção 9 nos dois clientes...")
        for c in clientes.values():
            c.esperar("Opção:")
            c.digitar("9")
        for c in clientes.values():
            c.esperar("conversa iniciada")
        time.sleep(0.3)

        for n, (quem, texto) in enumerate(MENSAGENS, start=1):
            outro = clientes["bob" if quem == "alice" else "alice"]
            print(f"  mensagem {n}: {quem} digita {texto!r}")
            clientes[quem].digitar(texto)
            outro.esperar(f"TEXTO ORIGINAL (mensagem #{n})")
            time.sleep(0.3)

        alice.encerrar()
        bob.encerrar()
    finally:
        servidor.encerrar()

    t_alice, t_bob, t_serv = limpar(alice.texto()), limpar(bob.texto()), limpar(servidor.texto())
    tabela = resumo(t_alice, t_bob, t_serv)

    def secao(titulo, corpo):
        barra = "#" * 78
        return f"\n{barra}\n# {titulo}\n{barra}\n{corpo}\n"

    relatorio = (
        "DEMONSTRAÇÃO -- Chat TCP com Diffie-Hellman + César (opção 9)\n"
        "Gerado por scripts/demonstracao_dh.py com os programas reais.\n"
        "Números de 617 dígitos aparecem resumidos: começo...fim (tamanho).\n"
        + tabela
        + secao("TERMINAL DO SERVIDOR", t_serv)
        + secao("TERMINAL DA ALICE (client.py)", t_alice)
        + secao("TERMINAL DO BOB (client.py)", t_bob)
    )
    os.makedirs(os.path.dirname(SAIDA), exist_ok=True)
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(relatorio)

    print(tabela)
    print(f"\nTerminais completos gravados em {os.path.relpath(SAIDA, RAIZ)}")


if __name__ == "__main__":
    main()
