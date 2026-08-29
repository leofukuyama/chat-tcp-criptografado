import threading
import socket
import sys

import ascii_puro

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

clients = []       # lista de sockets dos clientes conectados
enderecos = []     # lista paralela de endereços (mesmo índice de clients)
lock = threading.Lock()  # protege clients/enderecos contra race conditions
running = True      # flag global: controla o encerramento ordenado do servidor

CONTROLE_SAIR = "/sair"      # comando de controle: texto puro, nunca cifrado
PREFIXO_SISTEMA = "SYS:"     # marca mensagens geradas pelo servidor (não cifradas),
                              # para o cliente saber que NÃO deve tentar decifrar

# O chat é anônimo: não existe apelido em lugar nenhum do protocolo. As
# mensagens de entrada e saída são genéricas de propósito. O endereço de
# quem conectou fica SÓ no log do console do servidor, nunca é transmitido
# aos outros clientes.
AVISO_ENTRADA = "Alguem entrou no chat :D"
AVISO_SAIDA = "Alguem saiu do chat ;-;"


def formatar_endereco(address) -> str:
    """address vem do accept() como tupla (ip, porta)."""
    ip, porta = address
    return f"{ip}:{porta}"


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


def broadcast_texto(texto, remetente=None):
    """
    CAMADA 2 da defesa ASCII: todo texto gerado pelo próprio servidor sai
    por aqui, e ascii_puro.codificar() usa errors="strict".

    Se algum dia alguém escrever um aviso com acento ("Alguém entrou"), isso
    estoura em vez de vazar bytes não-ASCII na rede -- o erro aparece no
    console do servidor, onde dá para corrigir.
    """
    broadcast_raw(ascii_puro.codificar(texto), remetente=remetente)


# ============================================================
# GERENCIAMENTO DE DESCONEXÃO
# ============================================================

def remover_cliente(client, avisar=True, motivo="saiu do chat"):
    """
    Remove um cliente das listas compartilhadas e notifica o restante da sala.

    O parâmetro `motivo` tem DOIS destinos diferentes e propositalmente
    separados:
      - vai para o print() do console do servidor (log técnico, detalhado,
        só visível para quem está operando o servidor);
      - NÃO vai para a mensagem pública enviada aos outros clientes, que é
        sempre um texto fixo e genérico. O usuário do chat não precisa saber
        SE a saída foi por /sair, erro de rede, ou outro motivo técnico --
        só que alguém saiu.
    """
    with lock:
        if client in clients:
            index = clients.index(client)
            clients.remove(client)
            endereco = enderecos.pop(index)
        else:
            endereco = None

    if endereco:
        # Log interno do servidor: pode ser técnico/detalhado.
        print(f"[DESCONECTADO] {endereco} — {motivo}")

        if avisar:
            # Mensagem pública, SEMPRE com o mesmo texto fixo,
            # independentemente do motivo técnico da saída.
            broadcast_texto(f"{PREFIXO_SISTEMA}{AVISO_SAIDA}")

    return endereco


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
    broadcast_texto(CONTROLE_SAIR)

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

def handle(client, endereco):
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

            # --- CAMADA 3 da defesa ASCII: o ponto de estrangulamento ---
            # Este é o único lugar por onde todo o tráfego do chat passa, e
            # é o que garante o requisito mesmo contra um cliente
            # ADULTERADO -- alguém pode reescrever o client.py para pular a
            # validação de entrada e mandar bytes arbitrários no socket,
            # mas não consegue fazer esses bytes chegarem a mais ninguém.
            #
            # O frame é descartado, e só. A conexão NÃO é derrubada: um
            # cliente com bug perderia a sessão inteira por causa de uma
            # mensagem, e descartar já cumpre o requisito de que nada
            # não-ASCII trafegue.
            try:
                texto = ascii_puro.decodificar(dado)
            except ascii_puro.ErroAscii as erro:
                print(f"[BLOQUEADO] frame de {endereco} descartado — {erro}")
                continue

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
    Fica em loop aceitando novas conexões. Para cada cliente novo, sobe uma
    thread dedicada (handle()) para cuidar daquele cliente dali em diante.

    Não existe handshake de identidade: o chat é anônimo. Antes havia uma
    troca de apelido aqui, que além de trafegar sem validação nem cifra,
    bloqueava este laço em recv() -- uma conexão nova só era aceita depois
    que a anterior respondesse.
    """
    while running:
        try:
            client, address = server.accept()
        except OSError:
            # Acontece quando fechamos o server.close() de propósito
            # durante o encerramento (encerrar_tudo()).
            break

        endereco = formatar_endereco(address)
        print(f"Conectado com {endereco}")

        with lock:
            enderecos.append(endereco)
            clients.append(client)

        # Notifica os demais clientes (texto puro, marcado com o prefixo
        # de sistema, para eles saberem que não devem tentar decifrar isso).
        broadcast_texto(f"{PREFIXO_SISTEMA}{AVISO_ENTRADA}", remetente=client)

        thread = threading.Thread(target=handle, args=(client, endereco), daemon=True)
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
print("Modo ASCII: frames com qualquer byte fora de 0-127 são descartados.")

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
