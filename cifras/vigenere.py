"""
Cifra de Vigenère.
Chave: palavra só de letras, repetida ao longo da mensagem.
Espaços/pontuação não avançam a chave.
C = (P + K) mod 26   |   P = (C - K + 26) mod 26
"""

import string

import ascii_puro

# Letras que esta cifra sabe tratar: só o alfabeto latino ASCII, maiúsculo e
# minúsculo. Qualquer outra "letra" (grego, cirílico, ß) fica de fora.
LETRAS_ASCII = string.ascii_letters


def _eh_letra_ascii(caractere: str) -> bool:
    """
    Substitui o isalpha() usado antes em todo o módulo.

    isalpha() é verdadeiro para QUALQUER letra Unicode, e isso causava dois
    defeitos reais:
      - 'Ω' entrava na conta como se fosse letra latina, o "% 26" destruía o
        valor, e o texto decifrado nunca voltava ao original (perda silenciosa);
      - 'ß'.upper() devolve 'SS' (dois caracteres), e ord() estourava
        TypeError -- ou seja, digitar 'ß' no chat derrubava o cliente.

    Restringindo a A-Z ASCII, esses caracteres passam direto como pontuação:
    não são cifrados, mas também não são corrompidos nem quebram nada.
    """
    return caractere in LETRAS_ASCII


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    Valida se a chave pode ser usada na cifra.

    Regras:
        - não pode ser vazia
        - depois de normalizada (sem acento), deve conter apenas letras A-Z

    A normalização vem antes para que "cháve" seja aceita -- é exatamente o
    que cifrar() faz com ela. Já uma chave em grego ou cirílico é rejeitada:
    a cifra não sabe converter essas letras em deslocamento.

    Retorna:
        (True, "")           -> se a chave for válida
        (False, "mensagem")  -> se for inválida, junto do motivo
    """
    if not chave:
        return False, "A chave não pode ser vazia."

    chave_normalizada = ascii_puro.normalizar(chave)
    if not all(_eh_letra_ascii(c) for c in chave_normalizada):
        return False, "A chave deve conter apenas letras de A a Z."

    return True, ""


def _preparar_chave(chave: str) -> str:
    """
    Normaliza a chave e garante que ela é utilizável, ANTES de qualquer
    conta depender dela.

    Existe porque cifrar()/decifrar() não podem confiar em ter sido
    chamadas depois de validar_chave(): o chat valida, mas os testes e
    qualquer outro chamador podem não validar. Sem esta checagem, chave
    vazia estourava ZeroDivisionError lá dentro, em "j % len(chave)" --
    um erro que não diz absolutamente nada sobre a causa real.

    A regra NÃO é duplicada aqui de propósito: quem decide o que é uma
    chave válida continua sendo validar_chave(), para não existirem duas
    respostas diferentes para a mesma pergunta.

    >>> _preparar_chave("cháve")
    'CHAVE'
    """
    valida, erro = validar_chave(chave)
    if not valida:
        raise ValueError(erro)
    return _normalizar(chave).upper()


def _normalizar(texto: str) -> str:
    """
    Remove acentos do texto, mantendo a letra "base".

    Exemplo: "Ã" -> "A", "ç" -> "c", "É" -> "E"

    Como funciona:
        1. unicodedata.normalize("NFD", texto) separa cada letra acentuada
           em dois caracteres: a letra base + o acento (caractere combinante).
           Ex.: "ã" vira "a" + "~" (dois caracteres distintos).
        2. unicodedata.category(c) != "Mn" filtra fora qualquer caractere
           que seja uma "marca não-espaçada" (Mn = Mark, nonspacing),
           ou seja, remove o acento e mantém só a letra base.

    Espaços, números e pontuação não são afetados por essa função.

    A implementação vive em ascii_puro.normalizar(), compartilhada por todas
    as cifras. Note que ela NÃO mexe em maiúsculas/minúsculas -- é justamente
    disso que esta cifra depende para preservar a caixa do texto original.
    """
    return ascii_puro.normalizar(texto)


def cifrar(texto: str, chave: str) -> str:
    """
    Cifra um texto usando a Cifra de Vigenère.

    Fórmula aplicada a cada letra:
        Ci = (Pi + Ki mod m) mod 26

    Onde:
        Pi = número da i-ésima letra do texto (A=0, B=1, ..., Z=25)
        Ki = número da letra da chave correspondente à posição da letra
        m  = tamanho da chave (faz a chave repetir em ciclo)
        Ci = número da letra cifrada resultante

    Regras de negócio:
        - Acentos são removidos antes de cifrar (Ã -> A).
        - Espaços, números e pontuação são mantidos no resultado,
          mas NÃO avançam a posição da chave (não "gastam" uma letra dela).
        - Maiúsculas/minúsculas do texto original são preservadas no resultado.
    """
    # 1) Normaliza texto e chave (remove acentos, chave sempre em maiúsculas
    #    para facilitar o cálculo do deslocamento). _preparar_chave também
    #    recusa chave vazia ou fora de A-Z, com mensagem explicando o motivo.
    texto = _normalizar(texto)
    chave = _preparar_chave(chave)

    resultado = []
    j = 0  # índice que percorre a CHAVE; só avança quando cifra uma letra de verdade

    # 2) Percorre cada caractere do texto (i-ésima posição)
    for letra in texto:

        # 2.1) Caracteres que não são letras de A-Z (espaço, vírgula, número,
        #      ou letra de outro alfabeto) são mantidos como estão e NÃO
        #      avançam a chave (o "j" não muda)
        if not _eh_letra_ascii(letra):
            resultado.append(letra)
            continue

        # 2.2) Guarda se a letra original era maiúscula ou minúscula,
        #      para devolver o resultado no mesmo padrão de caixa
        base = ord('A') if letra.isupper() else ord('a')

        # 2.3) Converte a letra do texto para número (Pi)
        #      Ex.: 'T' -> ord('T') - ord('A') = 19
        P = ord(letra.upper()) - ord('A')

        # 2.4) Descobre qual letra da chave usar nesta posição (Ki mod m)
        #      "j % len(chave)" faz a chave repetir em ciclo:
        #      quando j chega no tamanho da chave, ela volta pro início.
        K = ord(chave[j % len(chave)]) - ord('A')

        # 2.5) Aplica a fórmula da cifra: Ci = (Pi + Ki) mod 26
        #      O "mod 26" garante que o resultado sempre "dê a volta"
        #      no alfabeto (equivalente a um relógio que volta ao zero após Z)
        C = (P + K) % 26

        # 2.6) Converte o número cifrado (C) de volta para letra,
        #      já respeitando se era maiúscula ou minúscula (base)
        resultado.append(chr(C + base))

        # 2.7) Só avança a chave quando uma LETRA de verdade foi cifrada
        j += 1

    # 3) Junta a lista de caracteres processados em uma única string
    return "".join(resultado)


def decifrar(texto: str, chave: str) -> str:
    """
    Decifra um texto que foi cifrado pela função cifrar().

    Fórmula aplicada a cada letra (processo inverso da cifragem):
        Pi = (Ci - Ki mod m + 26) mod 26

    O "+ 26" antes do mod é necessário porque, em Python, o resultado de uma
    subtração pode ficar negativo (ex.: 2 - 10 = -8). Somar 26 antes do mod
    garante que o resultado final sempre fique dentro do intervalo 0-25.

    Segue a mesma estrutura e regras de negócio da função cifrar():
        - acentos são removidos antes de processar
        - espaços/pontuação são mantidos e não avançam a chave
        - maiúsculas/minúsculas são preservadas
    """
    # 1) Mesma normalização (e mesma validação) feita na cifragem
    texto = _normalizar(texto)
    chave = _preparar_chave(chave)

    resultado = []
    j = 0  # índice que percorre a CHAVE, igual na função cifrar()

    # 2) Percorre cada caractere do texto cifrado
    for letra in texto:

        # 2.1) Caracteres que não são letras de A-Z são mantidos e não
        #      avançam a chave (mesma regra da cifragem)
        if not _eh_letra_ascii(letra):
            resultado.append(letra)
            continue

        # 2.2) Preserva o padrão de caixa (maiúscula/minúscula) do texto cifrado
        base = ord('A') if letra.isupper() else ord('a')

        # 2.3) Converte a letra cifrada para número (Ci)
        C = ord(letra.upper()) - ord('A')

        # 2.4) Descobre a letra da chave correspondente a esta posição (Ki mod m)
        K = ord(chave[j % len(chave)]) - ord('A')

        # 2.5) Aplica a fórmula inversa: Pi = (Ci - Ki + 26) mod 26
        #      Subtrai o deslocamento da chave para "desfazer" a cifragem
        P = (C - K + 26) % 26

        # 2.6) Converte o número decifrado (P) de volta para letra
        resultado.append(chr(P + base))

        # 2.7) Só avança a chave quando uma LETRA de verdade foi decifrada
        j += 1

    # 3) Junta tudo em uma única string
    return "".join(resultado)
