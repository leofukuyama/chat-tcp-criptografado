"""
Camada de defesa ASCII do chat.

REQUISITO: apenas ASCII (0-127) pode circular na rede. Nenhum outro tipo de
comunicação é permitido.

Este é o ponto ÚNICO de verdade sobre charset no projeto -- client.py e
server.py nunca chamam encode()/decode() diretamente, sempre passam por aqui.
Centralizar importa: enquanto as chamadas de encode("utf-8") estavam
espalhadas pelos dois arquivos, cada uma era uma chance independente de
esquecer a validação.

Acento é caso à parte. A seção 5 do enunciado EXIGE que as cifras normalizem
"Á" -> "A" e "Ç" -> "C", então texto acentuado é convertido, não rejeitado --
o que trafega continua sendo ASCII puro. Já o que não tem letra base ASCII
(emoji, "€", "ß", cirílico, CJK) é BLOQUEADO: nada é adivinhado, substituído
por "?" nem removido escondido. Alterar a mensagem do usuário sem ele saber
seria pior do que recusá-la.

DEFESA EM PROFUNDIDADE -- três camadas, porque uma só não basta: um cliente
adulterado pode pular a validação de entrada e escrever bytes arbitrários
direto no socket.

    Camada 1  validar() / preparar()   entrada do usuário, antes de cifrar
    Camada 2  codificar()              saída para a rede, errors="strict"
    Camada 3  decodificar()            entrada vinda da rede, byte a byte

A camada 3 no SERVIDOR é o ponto de estrangulamento: um frame com qualquer
byte fora de 0-127 é descartado e não repassado a ninguém. É o que garante o
requisito mesmo contra um cliente modificado.
"""

import unicodedata

# Maior valor de ponto de código aceito. ASCII é 0-127; 128 já é o primeiro
# byte fora da tabela.
MAIOR_CODIGO_ASCII = 127


class ErroAscii(ValueError):
    """
    Levantada quando um texto ou uma sequência de bytes contém algo fora do
    intervalo ASCII (0-127).

    Herda de ValueError de propósito: é um erro de VALOR do dado, não uma
    falha de rede. Isso mantém os blocos `except OSError` do chat -- que
    tratam queda de conexão -- separados do tratamento de charset, sem risco
    de um mascarar o outro.
    """


def normalizar(texto: str) -> str:
    """
    Remove acentos mantendo a letra base. Não garante ASCII na saída.

    Como funciona: NFD decompõe cada caractere acentuado em "letra base" +
    "marca combinante" (ex: "á" vira "a" + acento agudo, dois caracteres).
    Filtrando fora tudo que é marca não-espaçada (categoria Unicode "Mn"),
    sobra só a letra base.

    A cedilha sai de graça nesse processo: "ç" decompõe em "c" + cedilha
    combinante, que também é categoria "Mn". Por isso não existe aqui o
    replace("Ç", "C") manual que os módulos de cifra faziam -- era redundante.

    NÃO mexe em maiúsculas/minúsculas. Vigenère depende disso para preservar
    a caixa do texto original; quem quer caixa alta aplica .upper() depois.

    >>> normalizar("Ação, já!")
    'Acao, ja!'
    >>> normalizar("José")
    'Jose'
    """
    decomposto = unicodedata.normalize("NFD", texto)
    return "".join(c for c in decomposto if unicodedata.category(c) != "Mn")


def eh_ascii(texto: str) -> bool:
    """
    >>> eh_ascii("Ola mundo")
    True
    >>> eh_ascii("preco 50 euros") and not eh_ascii("preco €50")
    True
    """
    return all(ord(c) <= MAIOR_CODIGO_ASCII for c in texto)


def caracteres_invalidos(texto: str) -> list[str]:
    """
    Os caracteres fora do ASCII, sem repetição, na ordem em que aparecem.

    Sem repetição para que a mensagem de erro não fique ilegível quando o
    usuário cola um texto cheio do mesmo símbolo.

    >>> caracteres_invalidos("Ola mundo")
    []
    """
    vistos = []
    for c in texto:
        if ord(c) > MAIOR_CODIGO_ASCII and c not in vistos:
            vistos.append(c)
    return vistos


def descrever_invalidos(texto: str) -> str:
    """
    Descreve os caracteres não-ASCII de forma legível em QUALQUER console.

    Cada ofensor sai como U+XXXX, nunca impresso literalmente. Isso não é
    preciosismo: o console padrão do Windows é cp1252, e tentar imprimir um
    emoji nele levanta UnicodeEncodeError -- a mensagem de erro derrubaria o
    programa que ela deveria estar explicando.

    >>> descrever_invalidos("preco €50")
    'U+20AC'
    >>> descrever_invalidos("tudo ascii")
    ''
    """
    return ", ".join(f"U+{ord(c):04X}" for c in caracteres_invalidos(texto))


def validar(texto: str) -> tuple[bool, str]:
    """
    (True, "") se o texto for ASCII puro; (False, "motivo") caso contrário.

    Segue de propósito o mesmo contrato de validar_chave() dos módulos de
    cifra, para o cliente tratar os dois do mesmo jeito.

    NÃO normaliza. Responde sobre o texto que recebeu. Se normalizasse
    escondido, um texto acentuado passaria aqui e o chamador acharia que
    podia enviar os bytes originais -- que não são ASCII.

    >>> validar("Ola mundo")
    (True, '')
    """
    invalidos = caracteres_invalidos(texto)
    if not invalidos:
        return True, ""

    plural = "caracteres não-ASCII" if len(invalidos) > 1 else "caractere não-ASCII"
    return False, f"{plural}: {descrever_invalidos(texto)}"


def preparar(texto: str) -> str:
    """
    CAMADA 1. Normaliza o texto do usuário e garante que sobrou ASCII puro.

    Acento vira letra base e passa; o que não tem letra base ASCII levanta
    ErroAscii, e o chamador avisa o usuário sem enviar nada.

    >>> preparar("Ola, ação!")
    'Ola, acao!'
    """
    normalizado = normalizar(texto)
    valido, erro = validar(normalizado)
    if not valido:
        raise ErroAscii(erro)
    return normalizado


def codificar(texto: str) -> bytes:
    """
    CAMADA 2. Converte texto em bytes para ir à rede.

    errors="strict" é a garantia final: mesmo que a camada 1 falhe ou seja
    contornada, é impossível um byte >= 0x80 sair deste processo -- vira
    exceção. Usar errors="replace" ou "ignore" aqui destruiria a garantia,
    trocando o caractere por "?" e deixando a mensagem sair adulterada.

    Não normaliza. Isto é transporte puro; normalizar aqui mascararia um bug
    da camada 1.

    >>> codificar("/sair")
    b'/sair'
    """
    try:
        return texto.encode("ascii", errors="strict")
    except UnicodeEncodeError as erro:
        raise ErroAscii(
            f"tentativa de enviar {descrever_invalidos(texto)} pela rede"
        ) from erro


def decodificar(dados: bytes) -> str:
    """
    CAMADA 3. Converte bytes vindos da rede em texto, recusando qualquer
    byte fora de 0-127.

    A verificação é feita ANTES de decodificar, e o critério é ASCII -- não
    "decodificável". UTF-8 bem formado também é recusado: "ação" em UTF-8
    são bytes válidos, mas não são ASCII, e o requisito é ASCII.

    Bytes vazios devolvem string vazia em vez de erro: recv() vazio sinaliza
    conexão fechada, que é um evento normal tratado pelo chamador, não um
    problema de charset.

    >>> decodificar(b"SYS:alguem entrou")
    'SYS:alguem entrou'
    """
    altos = sorted({b for b in dados if b > MAIOR_CODIGO_ASCII})
    if altos:
        codigos = ", ".join(f"0x{b:02X}" for b in altos)
        raise ErroAscii(f"bytes fora do ASCII recebidos: {codigos}")

    return dados.decode("ascii", errors="strict")
