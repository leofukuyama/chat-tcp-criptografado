"""
Cifra de Playfair.
Chave: palavra/expressão em letras (J normalizado para I).
Matriz 5x5. Mensagem separada em pares, com regras de preenchimento com X.
Comunicação (espaços, números e pontuação preservados na posição
original) segue o mesmo formato de cesar.py -- só as LETRAS são
transformadas; o resto passa direto.
"""

import unicodedata

# 25 letras (sem J -- J é tratado como I, igual à matriz da cifra).
ALFABETO = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    >>> validar_chave("chave")
    (True, '')
    >>> validar_chave("123")
    (False, 'A chave deve conter ao menos uma letra.')
    """
    letras = [c for c in chave.upper() if c.isalpha()]
    if not letras:
        return False, "A chave deve conter ao menos uma letra."
    return True, ""


def _normalizar(texto: str) -> str:
    """
    Mesma regra de cesar.py/monoalfabetica.py (maiúsculas, Ç->C, sem
    acento). Espaços, números e pontuação ficam inalterados e nas
    MESMAS posições -- é isso que garante a saída no mesmo formato.

    >>> _normalizar("Ação, já!")
    'ACAO, JA!'
    """
    texto = texto.upper()
    texto = texto.replace("Ç", "C")

    texto_decomposto = unicodedata.normalize("NFD", texto)
    texto_sem_acento = "".join(
        c for c in texto_decomposto if unicodedata.category(c) != "Mn"
    )
    return texto_sem_acento


def _extrair_letras(texto_normalizado: str) -> list[str]:
    """
    Só as letras, na ordem em que aparecem, com J fundido em I.

    >>> _extrair_letras("ACAO, JA!")
    ['A', 'C', 'A', 'O', 'I', 'A']
    """
    return ["I" if c == "J" else c for c in texto_normalizado if c.isalpha()]


def _montar_matriz(chave: str) -> list[str]:
    """
    Monta a matriz 5x5: letras da chave (sem repetição, na ordem em que
    aparecem) seguidas do restante do alfabeto de 25 letras.
    Retorna uma lista de 5 strings, cada uma representando uma linha.

    Com a chave "PLAYFAIR EXAMPLE", a matriz fica assim (I e J dividem
    a mesma célula):

        P   L A Y F
        I/J R E X M
        B   C D G H
        K   N O Q S
        T   U V W Z

    >>> _montar_matriz("PLAYFAIR EXAMPLE")
    ['PLAYF', 'IREXM', 'BCDGH', 'KNOQS', 'TUVWZ']
    """
    letras_chave = _extrair_letras(_normalizar(chave))

    letras_usadas = []
    for c in letras_chave + list(ALFABETO):
        if c not in letras_usadas:
            letras_usadas.append(c)

    return ["".join(letras_usadas[i : i + 5]) for i in range(0, 25, 5)]


def _localizar(matriz: list[str], letra: str) -> tuple[int, int]:
    """
    >>> matriz = _montar_matriz("PLAYFAIR EXAMPLE")
    >>> _localizar(matriz, "H")
    (2, 4)
    """
    for linha in range(5):
        coluna = matriz[linha].find(letra)
        if coluna != -1:
            return linha, coluna
    raise ValueError(f"Letra '{letra}' não está na matriz.")


def _montar_pares(letras: list[str]) -> list[tuple[str, bool, str, bool]]:
    """
    Agrupa as letras em pares (regras clássicas do Playfair):
      - par com as duas letras iguais -> insere X no lugar da segunda;
      - letra sobrando no final (quantidade ímpar) -> completa com X.
    Cada item retornado é (letra_a, a_é_real, letra_b, b_é_real); a
    marcação "é_real" diz se a letra veio do texto original ou se é um
    X de preenchimento -- usado depois para saber onde encaixar cada
    letra cifrada na reconstrução da mensagem.

    >>> _montar_pares(["H", "E", "L", "L", "O"])
    [('H', True, 'E', True), ('L', True, 'X', False), ('L', True, 'O', True)]
    """
    pares = []
    i = 0
    while i < len(letras):
        a = letras[i]
        if i + 1 < len(letras) and letras[i + 1] != a:
            pares.append((a, True, letras[i + 1], True))
            i += 2
        else:
            pares.append((a, True, "X", False))
            i += 1
    return pares


def _transformar_par(matriz: list[str], a: str, b: str, passo: int) -> tuple[str, str]:
    """
    Aplica a regra de linha/coluna/retângulo do Playfair a um par de
    letras. `passo` = 1 para cifrar (desloca para a direita/baixo) e
    -1 para decifrar (desloca para a esquerda/cima). A regra do
    retângulo é a mesma nos dois sentidos, pois é sua própria inversa.

    >>> matriz = _montar_matriz("PLAYFAIR EXAMPLE")
    >>> _transformar_par(matriz, "H", "I", 1)
    ('B', 'M')
    """
    la, ca = _localizar(matriz, a)
    lb, cb = _localizar(matriz, b)

    if la == lb:
        return matriz[la][(ca + passo) % 5], matriz[lb][(cb + passo) % 5]
    if ca == cb:
        return matriz[(la + passo) % 5][ca], matriz[(lb + passo) % 5][cb]
    return matriz[la][cb], matriz[lb][ca]


def cifrar(texto: str, chave: str) -> str:
    """
    >>> cifrar("HELLO WORLD", "PLAYFAIR EXAMPLE")
    'DMYRAN VQCRGE'
    """
    matriz = _montar_matriz(chave)
    texto_normalizado = _normalizar(texto)
    letras = _extrair_letras(texto_normalizado)
    pares = _montar_pares(letras)

    # saida: sequência achatada de (letra_cifrada, é_real), na mesma
    # ordem das letras originais -- os X de preenchimento entram
    # intercalados, marcados como não-reais.
    saida = []
    for a, a_real, b, b_real in pares:
        ca, cb = _transformar_par(matriz, a, b, 1)
        saida.append((ca, a_real))
        saida.append((cb, b_real))

    resultado = []
    j = 0
    for c in texto_normalizado:
        if c.isalpha():
            resultado.append(saida[j][0])
            j += 1
            # X de preenchimento por letra duplicada gruda logo depois
            # da letra que o originou, antes do próximo caractere real
            while j < len(saida) and not saida[j][1]:
                resultado.append(saida[j][0])
                j += 1
        else:
            resultado.append(c)

    # X de preenchimento do último par, se a mensagem tiver número
    # ímpar de letras (não tem caractere original para grudar depois)
    while j < len(saida):
        resultado.append(saida[j][0])
        j += 1

    return "".join(resultado)


def _remover_x_de_preenchimento(caracteres: list[str]) -> list[str]:
    """
    Limpeza heurística dos X inseridos por cifrar(): remove um X quando
    está entre duas letras iguais (LXL -> LL, caso de letra duplicada)
    e remove um X isolado que sobra como última letra da mensagem
    (padding de texto com número ímpar de letras).

    Não há garantia absoluta -- se a mensagem original genuinamente
    tivesse um X nessas posições (ex.: terminar em "RAIO X"), ele
    também seria removido por engano. É a mesma ambiguidade que existe
    ao decifrar Playfair manualmente: o X de preenchimento só se
    distingue de um X real pelo contexto.

    >>> "".join(_remover_x_de_preenchimento(list("HELXLO WORLDX")))
    'HELLO WORLD'
    """
    sem_duplicatas = []
    for i, c in enumerate(caracteres):
        if (
            c == "X"
            and 0 < i < len(caracteres) - 1
            and caracteres[i - 1].isalpha()
            and caracteres[i - 1] == caracteres[i + 1]
        ):
            continue
        sem_duplicatas.append(c)

    indices_letras = [i for i, c in enumerate(sem_duplicatas) if c.isalpha()]
    if indices_letras and sem_duplicatas[indices_letras[-1]] == "X":
        del sem_duplicatas[indices_letras[-1]]

    return sem_duplicatas


def decifrar(texto: str, chave: str) -> str:
    """
    Não normaliza o texto de novo aqui: o texto recebido já é o
    CIFRADO, no mesmo formato produzido por cifrar() -- espaços,
    números e pontuação já estão na posição final.

    >>> decifrar("DMYRAN VQCRGE", "PLAYFAIR EXAMPLE")
    'HELLO WORLD'
    """
    matriz = _montar_matriz(chave)
    letras_cifradas = [c for c in texto if c.isalpha()]

    letras_decifradas = []
    for i in range(0, len(letras_cifradas) - 1, 2):
        pa, pb = _transformar_par(matriz, letras_cifradas[i], letras_cifradas[i + 1], -1)
        letras_decifradas.append(pa)
        letras_decifradas.append(pb)

    resultado = []
    it = iter(letras_decifradas)
    for c in texto:
        resultado.append(next(it) if c.isalpha() else c)

    return "".join(_remover_x_de_preenchimento(resultado))
