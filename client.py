import socket
import threading
import sys
import os
import signal

import ascii_puro
import protocolo
from cifras.registro import CIFRAS, NOMES
from sessao_dh import SessaoDH

# ============================================================
# CONEXÃO
# ============================================================
# O chat é anônimo: não há apelido nem handshake de identidade. Antes o
# apelido era pedido aqui e enviado ao servidor em texto puro, sem passar
# por cifra nenhuma e sem validação de charset -- era o caminho mais fácil
# para bytes não-ASCII entrarem na rede.

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 64146))

# ============================================================
# ESTADO DE CONTROLE COMPARTILHADO ENTRE AS THREADS
# ============================================================

running = True            # controla o loop principal de envio/recebimento
saida_voluntaria = False  # diferencia "eu decidi sair" de "o servidor caiu"
COMANDO_SAIR = "/sair"
COMANDO_PARTICIPANTES = "/participantes"

# Só existe na opção 9 (Diffie-Hellman + César). Nas outras fica None e o
# chat funciona exatamente como antes.
sessao = None
aviso_dh_mostrado = False


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

        if getattr(modulo, "NEGOCIA_CHAVE_POR_MENSAGEM", False):
            # Opção 9: não há chave para digitar nem para combinar por fora.
            # Ela é negociada pela rede, a cada mensagem, por Diffie-Hellman.
            # p e g são constantes: a prova de que são adequados é feita uma
            # vez, pelos testes e por scripts/verificar_parametros_dh.py, e
            # não a cada vez que o chat abre.
            print(
                f"\nParâmetros públicos de Diffie-Hellman (fixos, iguais nos dois clientes):\n"
                f"  p = primo seguro de {modulo.P.bit_length()} bits (RFC 3526, grupo 14)\n"
                f"  g = {modulo.G} (raiz primitiva de p)\n"
                f"  Justificativa: python scripts/verificar_parametros_dh.py"
            )
            print("Cada mensagem terá uma negociação NOVA e uma chave de César própria.")
            return modulo, ""

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
# EXIBIÇÃO DE UM QUADRO RECEBIDO
# ============================================================

def mostrar_quadro(quadro, modulo, chave):
    """
    Decide o que fazer com um quadro completo vindo do servidor.
    Devolve False quando o cliente deve encerrar.

    A decisão é tomada pelo TIPO declarado no cabeçalho, não por inspeção do
    conteúdo. Antes o código perguntava `if dado == "/sair"` e
    `if dado.startswith("SYS:")`, o que confundia mensagem de chat com aviso
    do servidor e permitia falsificação.
    """
    # Payload não-ASCII: o servidor já barra, mas o cliente não confia nisso
    # -- verificar dos dois lados é o que torna a garantia independente de
    # quem está do outro lado da conexão.
    if quadro.texto is None:
        print(f"\r*** mensagem descartada: {quadro.erro} ***\n > ", end="", flush=True)
        return True

    if quadro.tipo == protocolo.TIPO_CONTROLE:
        if quadro.texto == COMANDO_SAIR:
            print("\rServidor encerrado pelo administrador.")
            encerrar_por_desconexao()
            return False

        # "/participantes N": quantas pessoas há na sala (enviado pelo
        # servidor a cada entrada e saída). Só a opção 9 precisa disso:
        # negociar sozinho travaria a sessão esperando um B que não vem.
        partes = quadro.texto.split(" ")
        if partes[0] == COMANDO_PARTICIPANTES and len(partes) == 2 and partes[1].isdigit():
            if sessao is not None:
                sessao.definir_participantes(int(partes[1]))
                print(" > ", end="", flush=True)
        return True

    if quadro.tipo == protocolo.TIPO_SISTEMA:
        # Nunca foi cifrado: tentar decifrar isso geraria lixo.
        print(f"\r*** {quadro.texto} ***\n > ", end="", flush=True)
        return True

    # --- Opção 9: Diffie-Hellman + César ---
    # Tanto a negociação (D) quanto o texto cifrado (M) vão para a sessão,
    # que guarda a chave negociada para esta mensagem.
    if sessao is not None:
        if quadro.tipo == protocolo.TIPO_NEGOCIACAO:
            sessao.receber_negociacao(quadro.texto)
        else:
            sessao.receber_mensagem(quadro.texto)
        print(" > ", end="", flush=True)
        return True

    if quadro.tipo == protocolo.TIPO_NEGOCIACAO:
        # Este cliente não está na opção 9, mas o outro está.
        global aviso_dh_mostrado
        if not aviso_dh_mostrado:
            aviso_dh_mostrado = True
            print(
                "\r*** o outro participante está usando Diffie-Hellman (opção 9); "
                "escolha a mesma opção para conversar ***\n > ",
                end="", flush=True,
            )
        return True

    # Conteúdo de chat real: só aqui decifra de fato.
    texto_claro = modulo.decifrar(quadro.texto, chave)
    print(f"\r[CIFRADO]   {quadro.texto}")

    # Extensão OPCIONAL do contrato das cifras (cifras/sem_criptografia.py):
    # só o RC4 tem um criptograma que não é ASCII "de fábrica" -- por isso
    # trafega em Base64 -- e expõe bytes_brutos() para mostrar os mesmos
    # bytes em decimal e em hexadecimal (formato dos slides da disciplina).
    # As outras cifras não têm essa função porque o texto já cifrado ali
    # em cima já é a própria informação, sem camada extra.
    if hasattr(modulo, "bytes_brutos"):
        brutos = modulo.bytes_brutos(quadro.texto)
        print(f"[CIFRADO decimal] {list(brutos)}")
        print(f"[CIFRADO hexadecimal] {brutos.hex(' ').upper()}")

    print(f"[DECIFRADO] {texto_claro}")
    
    if hasattr(modulo, "bytes_brutos"):
        # Texto plano em hexadecimal (sem o padding de zeros), como no slide.
        if quadro.texto.startswith("H:"):
            print(f"[DECIFRADO hexadecimal] {texto_claro}")
        else:
            print(
                f"[DECIFRADO hexadecimal] "
                f"{texto_claro.encode('ascii', 'replace').hex(' ').upper()}"
            )

    print(" > ", end="", flush=True)
    return True


# ============================================================
# THREAD DE RECEBIMENTO (roda em background)
# ============================================================

def receive(modulo, chave):
    """
    Fica em loop recebendo dados do servidor, remontando quadros completos e
    despachando cada um para mostrar_quadro().

    O desempacotador é o que corrige o defeito de enquadramento: duas
    mensagens que chegam grudadas em um recv() saem daqui como dois quadros
    separados, e uma mensagem picada entre dois recv() é remontada.
    """
    global running
    desempacotador = protocolo.Desempacotador()

    while running:
        try:
            dado = client.recv(1024)

            # --- Conexão encerrada (recv retornou vazio) ---
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

            try:
                quadros = desempacotador.alimentar(dado)
            except protocolo.ErroProtocolo as erro:
                # Cabeçalho corrompido: não dá para saber onde este quadro
                # termina, então não dá para pular só ele. Seguir seria
                # interpretar lixo.
                print(f"\rConexão encerrada — protocolo inválido: {erro}")
                encerrar_por_desconexao()
                break

            for quadro in quadros:
                if not mostrar_quadro(quadro, modulo, chave):
                    return

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

def enviar(tipo, texto):
    """Empacota e manda. Devolve False se a conexão caiu."""
    try:
        client.send(protocolo.empacotar(tipo, texto))
        return True
    except OSError:
        return False


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

        if msg.strip() == COMANDO_SAIR:
            # Saída voluntária e individual: só esse cliente sai.
            saida_voluntaria = True
            enviar(protocolo.TIPO_CONTROLE, COMANDO_SAIR)
            running = False
            break

        # --- CAMADA 1 da defesa ASCII: entrada do usuário ---
        # Acento é normalizado ("ação" -> "acao"), como a seção 5 do
        # enunciado exige. O que não tem letra base ASCII (emoji, "€",
        # cirílico) é recusado AQUI, antes de cifrar: a mensagem não sai, o
        # usuário fica sabendo exatamente qual caractere causou o problema,
        # e o chat continua rodando normalmente.
        try:
            texto_claro = ascii_puro.preparar(msg)
        except ascii_puro.ErroAscii as erro:
            print(f"   Mensagem não enviada — só é permitido ASCII. Removido: {erro}")
            continue

        if sessao is not None:
            # Opção 9: a sessão faz os passos 1 a 8 (negocia, verifica,
            # cifra e envia). A chave só existe depois da negociação.
            sessao.enviar_texto(texto_claro)
            continue

        cifrado = modulo.cifrar(texto_claro, chave)
        print(f"   [CIFRADO]   {cifrado}")
        if hasattr(modulo, "bytes_brutos"):
            # Mesma extensão opcional usada em mostrar_quadro(): mostra o
            # que acabou de ser enviado em decimal e em hexadecimal (formato
            # dos slides da disciplina), sem precisar esperar o outro cliente responder.
            brutos = modulo.bytes_brutos(cifrado)
            print(f"   [CIFRADO decimal] {list(brutos)}")
            print(f"   [CIFRADO hexadecimal] {brutos.hex(' ').upper()}")
            # Texto plano em hexadecimal (sem o padding de zeros), como no slide.
            print(f"   [TEXTO PLANO hexadecimal] {texto_claro.encode('ascii', 'replace').hex(' ').upper()}")

        # empacotar() aplica a CAMADA 2 (errors="strict") e valida o
        # tamanho. Mesmo que a camada 1 falhasse, é impossível um byte
        # >= 0x80 sair deste processo.
        try:
            quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, cifrado)
        except ascii_puro.ErroAscii as erro:
            print(f"   Envio bloqueado pela verificação final de ASCII: {erro}")
            continue
        except protocolo.ErroProtocolo as erro:
            print(f"   Mensagem não enviada — {erro}")
            continue

        try:
            client.send(quadro)
        except OSError:
            print("\rNão foi possível enviar: conexão perdida.")
            running = False
            break


# ============================================================
# PONTO DE ENTRADA
# ============================================================

# A escolha de cifra é inteiramente local e não depende de nada vindo do
# servidor (ver escolher_cifra() acima). Não há handshake antes dela.
print("Chat em modo ASCII: acentos são convertidos, o resto não é aceito.")
modulo, chave = escolher_cifra()

if getattr(modulo, "NEGOCIA_CHAVE_POR_MENSAGEM", False):
    sessao = SessaoDH(
        enviar=enviar,
        exibir=lambda linha: print(f"\r{linha}", flush=True),
    )

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
    enviar(protocolo.TIPO_CONTROLE, COMANDO_SAIR)
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
