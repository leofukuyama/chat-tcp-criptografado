"""
Cifra de Vigenère.
Chave: palavra só de letras, repetida ao longo da mensagem.
Espaços/pontuação não avançam a chave.
C = (P + K) mod 26   |   P = (C - K + 26) mod 26
"""

import unicodedata


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    Valida se a chave pode ser usada na cifra.

    Regras:
        - não pode ser vazia
        - deve conter apenas letras (sem números, espaços ou símbolos)

    Retorna:
        (True, "")           -> se a chave for válida
        (False, "mensagem")  -> se for inválida, junto do motivo
    """
    if not chave:
        return False, "A chave não pode ser vazia."
    if not chave.isalpha():
        return False, "A chave deve conter apenas letras."
    return True, ""


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
    """
    nfkd = unicodedata.normalize("NFD", texto)
    return "".join(caractere for caractere in nfkd if unicodedata.category(caractere) != "Mn")


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
    #    para facilitar o cálculo do deslocamento)
    texto = _normalizar(texto)
    chave = _normalizar(chave).upper()

    resultado = []
    j = 0  # índice que percorre a CHAVE; só avança quando cifra uma letra de verdade

    # 2) Percorre cada caractere do texto (i-ésima posição)
    for letra in texto:

        # 2.1) Caracteres que não são letras (espaço, vírgula, número...)
        #      são mantidos como estão e NÃO avançam a chave (o "j" não muda)
        if not letra.isalpha():
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
    # 1) Mesma normalização feita na cifragem
    texto = _normalizar(texto)
    chave = _normalizar(chave).upper()

    resultado = []
    j = 0  # índice que percorre a CHAVE, igual na função cifrar()

    # 2) Percorre cada caractere do texto cifrado
    for letra in texto:

        # 2.1) Caracteres que não são letras são mantidos e não avançam a chave
        if not letra.isalpha():
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
