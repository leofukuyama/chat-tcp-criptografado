import socket
import threading
import sys
import os
import signal
from cifras.registro import CIFRAS, NOMES

# ============================================================
# IDENTIFICAÇÃO E CONEXÃO
# ============================================================

nickname = input("Digite seu apelido: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 64146))

# ============================================================
# ESTADO DE CONTROLE COMPARTILHADO ENTRE AS THREADS
# ============================================================

running = True            # controla o loop principal de envio/recebimento
saida_voluntaria = False  # diferencia "eu decidi sair" de "o servidor caiu"
CONTROLE_SAIR = "/sair"   # comando de controle: texto puro, nunca cifrado
PREFIXO_SISTEMA = "SYS:"  # marca mensagens de sistema (nunca cifradas)


# ============================================================
# SELEÇÃO DE CIFRA (100% LOCAL — não envolve o servidor)
# ============================================================

def escolher_cifra():
    """
    Pergunta ao usuário qual cifra e chave usar.

    Decisão de segurança importante: essa escolha NUNCA é enviada ao
    servidor nem combinada pela rede. A chave precisa ser acertada por
    fora (WhatsApp, telefone, presencialmente) entre todos os
    participantes do chat -- se fosse transmitida pela rede, o servidor
    (ou qualquer um capturando o tráfego) teria acesso a ela.
    """
    print("\nCombine com os outros participantes, por fora da rede, a mesma cifra e chave.")
    print("Escolha o modo de transmissão:")
    for opcao, nome in NOMES.items():
        print(f"{opcao} - {nome}")

    while True:
        opcao = input("Opção: ").strip()
        modulo = CIFRAS.get(opcao)
        if not modulo:
            print("Opção inválida.")
            continue

        if opcao == "1":
            return modulo, ""  # "sem criptografia" não usa chave

        chave = input("Chave: ").strip()
        valida, erro = modulo.validar_chave(chave)
        if not valida:
            print(f"Chave inválida: {erro}")
            continue

        return modulo, chave


# ============================================================
# TRATAMENTO DE Ctrl+C VINDO DE UMA THREAD SECUNDÁRIA
# ============================================================

def encerrar_por_desconexao():
    """
    Sinais do sistema operacional (como o SIGINT do Ctrl+C) só podem ser
    entregues e tratados pela thread PRINCIPAL em Python -- nunca por
    threads secundárias. Como é a thread receive() (secundária) que
    detecta quando a conexão caiu (servidor fechou, erro de rede), ela
    precisa "acordar" a thread principal, que está parada bloqueada em
    input(). Simulamos isso disparando um SIGINT para o próprio processo,
    reaproveitando o bloco de cleanup já existente no try/except principal.
    """
    global running
    running = False
    os.kill(os.getpid(), signal.SIGINT)


# ============================================================
# THREAD DE RECEBIMENTO (roda em background)
# ============================================================

def receive(modulo, chave):
    """
    Fica em loop recebendo dados do servidor e decidindo o que fazer com
    cada um, na seguinte ordem de prioridade:
      1. Conexão caiu (dado vazio)?
      2. É um comando de controle (/sair global)?
      3. É o handshake de identidade (NICK)?
      4. É uma mensagem de sistema (entrada/saída de alguém)?
      5. Só então: é conteúdo de chat de verdade -> tenta decifrar.
    Essa ordem importa: pular a checagem 4 e tentar decifrar tudo faria
    o programa tentar decifrar textos que nunca foram cifrados (como
    "fulano entrou no chat"), gerando lixo.
    """
    global running
    while running:
        try:
            dado = client.recv(1024).decode("utf-8")

            # --- 1. Conexão encerrada (recv retornou vazio) ---
            if not dado:
                if saida_voluntaria:
                    # Fomos NÓS que fechamos o socket (via /sair ou Ctrl+C).
                    # A thread principal já sabe disso e já está no
                    # caminho de encerramento -- não precisa de SIGINT.
                    print("\rVocê saiu do chat.")
                else:
                    # O SERVIDOR fechou a conexão sem avisar via /sair
                    # (ex: caiu, foi derrubado). A thread principal está
                    # bloqueada em input() sem saber disso -- precisa ser
                    # acordada.
                    print("\rO servidor encerrou a conexão.")
                    encerrar_por_desconexao()
                running = False
                break

            # --- 2. Comando de controle: encerramento GLOBAL do servidor ---
            if dado == CONTROLE_SAIR:
                print("\rServidor encerrado pelo administrador.")
                encerrar_por_desconexao()
                break

            # --- 3. Handshake de identidade ---
            if dado == "NICK":
                client.send(nickname.encode("utf-8"))
                continue

            # --- 4. Mensagem de sistema (nunca foi cifrada) ---
            if dado.startswith(PREFIXO_SISTEMA):
                texto_sistema = dado[len(PREFIXO_SISTEMA):]
                print(f"\r*** {texto_sistema} ***\n > ", end="", flush=True)
                continue

            # --- 5. Conteúdo de chat real: só aqui decifra de fato ---
            texto_claro = modulo.decifrar(dado, chave)
            print(f"\r[CIFRADO]   {dado}")
            print(f"[DECIFRADO] {texto_claro}\n > ", end="", flush=True)

        except OSError:
            # Socket já fechado localmente (Ctrl+C tratado no bloco principal).
            running = False
            break
        except Exception as e:
            print(f"\rErro de conexão: {e}")
            encerrar_por_desconexao()
            break


# ============================================================
# LOOP DE ENVIO (roda na thread PRINCIPAL)
# ============================================================

def write(modulo, chave):
    """
    Fica em loop lendo o que o usuário digita, cifrando e enviando.
    Roda na thread principal de propósito: é a única thread capaz de
    receber o Ctrl+C (SIGINT) do sistema operacional, então o input()
    bloqueante precisa estar aqui, não em uma thread secundária.
    """
    global running, saida_voluntaria
    while running:
        msg = input(" > ")
        if not running:
            break

        if msg.strip() == CONTROLE_SAIR:
            # Saída voluntária e individual: só esse cliente sai.
            saida_voluntaria = True
            try:
                # Comando de controle: enviado em texto puro, nunca cifrado.
                client.send(CONTROLE_SAIR.encode("utf-8"))
            except OSError:
                pass
            running = False
            break

        # Mensagem de chat real: cifrada antes de sair pela rede.
        texto_claro = f"{nickname}: {msg}"
        cifrado = modulo.cifrar(texto_claro, chave)
        try:
            client.send(cifrado.encode("utf-8"))
        except OSError:
            print("\rNão foi possível enviar: conexão perdida.")
            running = False
            break


# ============================================================
# PONTO DE ENTRADA
# ============================================================

# --- Handshake inicial: só troca identidade (NICK). ---
# A escolha de cifra é inteiramente local e não depende de nada vindo
# do servidor (ver escolher_cifra() acima).
primeira_msg = client.recv(1024).decode("utf-8")
if primeira_msg == "NICK":
    client.send(nickname.encode("utf-8"))

modulo, chave = escolher_cifra()

# receive() roda em background (daemon=True): se a thread principal
# terminar, essa thread é derrubada automaticamente pelo interpretador.
receive_thread = threading.Thread(target=receive, args=(modulo, chave), daemon=True)
receive_thread.start()

try:
    # write() roda na thread principal -> aqui é onde o Ctrl+C
    # (KeyboardInterrupt) pode de fato ser recebido e tratado.
    write(modulo, chave)
except KeyboardInterrupt:
    print("\nEncerrando cliente...")
    saida_voluntaria = True
    try:
        client.send(CONTROLE_SAIR.encode("utf-8"))
    except OSError:
        pass
finally:
    # Cleanup final, executado em QUALQUER caminho de saída
    # (comando /sair, Ctrl+C, ou erro de rede).
    running = False
    try:
        # shutdown() avisa ativamente o servidor (pacote TCP FIN),
        # fazendo o recv() dele retornar de forma imediata e previsível.
        client.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client.close()
    sys.exit(0)