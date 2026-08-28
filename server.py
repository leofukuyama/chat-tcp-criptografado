import threading
import socket
import sys

# ============================================================
# CONFIGURAÇÃO E INICIALIZAÇÃO DO SOCKET DO SERVIDOR
# ============================================================

host = "127.0.0.1"
port = 64146

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Permite reutilizar a porta imediatamente após o servidor ser encerrado,
# sem precisar esperar o timeout de TIME_WAIT do SO (útil durante testes).
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen()

# ============================================================
# ESTADO COMPARTILHADO ENTRE THREADS
# ============================================================
# Cada cliente conectado gera sua própria thread (handle()), então essas
# estruturas são acessadas concorrentemente e precisam de proteção (lock).

clients = []        # lista de sockets dos clientes conectados
lock = threading.Lock()  # protege clients contra race conditions
running = True       # flag global: controla o encerramento ordenado do servidor

CONTROLE_SAIR = "/sair"      # comando de controle: texto puro, nunca cifrado
PREFIXO_SISTEMA = "SYS:"     # marca mensagens geradas pelo servidor (não cifradas),
                              # para o cliente saber que NÃO deve tentar decifrar


# ============================================================
# RELAY DE MENSAGENS
# ============================================================

def broadcast_raw(dado_bytes, remetente=None):
    """
    Repassa os bytes exatamente como chegaram para todos os clientes,
    exceto o remetente (se informado).

    IMPORTANTE (decisão de segurança): o servidor NUNCA chama cifrar()/
    decifrar() em lugar nenhum do programa. Ele só encaminha bytes crus.
    Isso garante que o servidor não tem acesso ao conteúdo das mensagens
    -- só quem tem a chave (os clientes) consegue interpretar o payload.
    """
    with lock:
        destinatarios = [c for c in clients if c != remetente]
    for c in destinatarios:
        try:
            c.send(dado_bytes)
        except OSError:
            pass


# ============================================================
# GERENCIAMENTO DE DESCONEXÃO
# ============================================================

def remover_cliente(client, avisar=True, motivo="saiu do chat"):
    """
    Remove um cliente da lista compartilhada e notifica o restante da sala.

    Sem nickname, não há mais nome para identificar o cliente publicamente
    -- a mensagem enviada aos outros participantes é sempre genérica.
    Para o log interno do servidor (só visível para quem está operando o
    servidor), usamos o endereço da conexão (ip:porta) como identificador,
    já que ele ainda está disponível no socket antes de fechá-lo.
    """
    endereco = None
    with lock:
        if client in clients:
            try:
                endereco = client.getpeername()
            except OSError:
                endereco = None
            clients.remove(client)

    if endereco is not None:
        # Log interno do servidor: pode ser técnico/detalhado.
        print(f"[DESCONECTADO] {endereco} — {motivo}")

        if avisar:
            # Mensagem pública, SEMPRE com o mesmo texto fixo,
            # independentemente do motivo técnico da saída.
            aviso = f"{PREFIXO_SISTEMA}Um participante saiu do chat ;-;"
            broadcast_raw(aviso.encode("utf-8"))


def encerrar_tudo():
    """
    Encerramento GLOBAL: derruba todos os clientes e o próprio servidor.
    Só é chamado a partir do console do servidor (comando /sair digitado
    pelo administrador) ou por Ctrl+C na thread principal do servidor.

    Diferença importante em relação ao /sair de um cliente individual:
    aqui a intenção é fechar a "sala" inteira, não só uma conexão.
    """
    global running
    print("\n[ADMIN] Encerrando servidor e todos os clientes...")

    # Avisa a todos os clientes conectados, em texto puro (comando de
    # controle, nunca cifrado), que a sessão global está encerrando.
    broadcast_raw(CONTROLE_SAIR.encode("utf-8"))

    running = False

    with lock:
        alvo = list(clients)

    for c in alvo:
        try:
            # shutdown() avisa ativamente o outro lado (pacote TCP FIN),
            # fazendo o recv() dele retornar imediatamente, em vez de só
            # detectar a queda depois de um timeout.
            c.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        c.close()

    try:
        server.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    server.close()


# ============================================================
# THREAD POR CLIENTE: recebe e repassa mensagens de UM cliente
# ============================================================

def handle(client):
    """
    Roda em uma thread dedicada para cada cliente conectado.
    Fica em loop recebendo dados desse cliente específico e repassando
    (via broadcast_raw) para os demais.
    """
    while True:
        try:
            dado = client.recv(1024)
            if not dado:
                # recv() vazio = o outro lado fechou a conexão sem seguir
                # o protocolo de /sair (ex: queda abrupta de rede).
                raise ConnectionResetError

            texto = dado.decode("utf-8")

            if texto == CONTROLE_SAIR:
                # Saída VOLUNTÁRIA E INDIVIDUAL: só esse cliente sai.
                # (Diferente de encerrar_tudo(), que é acionado pelo
                # console do servidor e derruba a sala inteira.)
                remover_cliente(client, motivo="saída voluntária (/sair)")
                try:
                    # Mesmo padrão de shutdown+close usado em encerrar_tudo(),
                    # por consistência: garante que o FIN seja enviado de
                    # forma determinística, não dependendo só do SO.
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
                break

            # Conteúdo de chat "de verdade": o servidor só EXIBE o payload
            # cifrado recebido (prova de que não está lendo o conteúdo) e
            # repassa os mesmos bytes adiante, sem decifrar.
            print(f"[CIFRADO recebido] {texto}")
            broadcast_raw(dado, remetente=client)

        except (ConnectionResetError, ConnectionAbortedError):
            # Queda abrupta: cliente fechou o terminal, perdeu rede, etc.
            remover_cliente(client, motivo="conexão perdida abruptamente")
            client.close()
            break
        except Exception:
            # Qualquer outra falha inesperada, como rede genérica.
            remover_cliente(client, motivo="erro de comunicação")
            client.close()
            break


# ============================================================
# THREAD DE ACEITAÇÃO DE NOVAS CONEXÕES
# ============================================================

def receive():
    """
    Fica em loop aceitando novas conexões. Para cada cliente novo, adiciona
    o socket à lista compartilhada e sobe uma thread dedicada (handle())
    para cuidar daquele cliente específico dali em diante.

    Não há mais handshake de identidade (NICK): o servidor não precisa de
    um nome para gerenciar o cliente, o próprio objeto socket já basta.
    """
    while running:
        try:
            client, address = server.accept()
        except OSError:
            # Acontece quando fechamos o server.close() de propósito
            # durante o encerramento (encerrar_tudo()).
            break

        print(f"Conectado com {address}")

        with lock:
            clients.append(client)

        # Notifica os demais clientes (texto puro, marcado com o prefixo
        # de sistema, para eles saberem que não devem tentar decifrar isso).
        aviso = f"{PREFIXO_SISTEMA}Um novo participante entrou no chat :D"
        broadcast_raw(aviso.encode("utf-8"), remetente=client)

        thread = threading.Thread(target=handle, args=(client,), daemon=True)
        thread.start()


# ============================================================
# CONSOLE DE ADMINISTRAÇÃO (roda na thread principal)
# ============================================================

def console_admin():
    """
    Lê comandos digitados diretamente no terminal do SERVIDOR.
    Esse é o único lugar onde /sair tem efeito GLOBAL (derruba tudo).
    Precisa rodar na thread principal, pois é a única thread que consegue
    receber sinais do sistema operacional (como o Ctrl+C / SIGINT).
    """
    while running:
        try:
            cmd = input()
        except EOFError:
            break
        if cmd.strip() == CONTROLE_SAIR:
            encerrar_tudo()
            break


# ============================================================
# PONTO DE ENTRADA
# ============================================================

print("Servidor está online... (digite /sair para encerrar tudo)")

# A aceitação de conexões roda em background (daemon), liberando a thread
# principal para ficar disponível ao console_admin() e a sinais do SO.
receive_thread = threading.Thread(target=receive, daemon=True)
receive_thread.start()

try:
    console_admin()
except KeyboardInterrupt:
    # Ctrl+C direto no terminal do servidor também derruba tudo.
    print("\nCtrl+C: encerrando servidor...")
    encerrar_tudo()

# Segurança extra: garante o cleanup mesmo se console_admin() retornar
# por outro caminho sem ter chamado encerrar_tudo() ainda.
if running:
    encerrar_tudo()

print("Servidor encerrado.")
sys.exit(0)