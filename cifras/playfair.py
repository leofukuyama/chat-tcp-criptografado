"""
Cifra de Playfair.
Chave: palavra/expressão em letras (J normalizado para I).
Matriz 5x5. Mensagem separada em pares, com regras de preenchimento com X.
Comunicação (espaços, números e pontuação preservados na posição
original) segue o mesmo formato de cesar.py -- só as LETRAS são
transformadas; o resto passa direto.
"""

import ascii_puro

# 25 letras (sem J -- J é tratado como I, igual à matriz da cifra).
ALFABETO = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

# Letra usada para separar um par de letras iguais e para completar um
# texto de tamanho ímpar.
FILLER = "X"

# Filler usado quando a própria letra duplicada é o X. Sem ele, "XX" vira
# o par (X, X) -- que as regras de linha e coluna não separam, porque
# deslocar duas letras idênticas devolve duas letras idênticas. O Playfair
# clássico troca de filler exatamente por isso.
FILLER_ALTERNATIVO = "Q"

FILLERS = (FILLER, FILLER_ALTERNATIVO)


def _eh_letra_da_matriz(caractere: str) -> bool:
    """
    Diz se este é um caractere que a matriz 5x5 sabe tratar.

    Substitui o isalpha() que era usado em todo o módulo. isalpha() é
    verdadeiro para qualquer letra Unicode, incluindo caracteres que não
    existem na matriz -- eles chegavam em _localizar() e levantavam
    ValueError, derrubando o cliente. Exemplo real: 'ŉ'.upper() == 'ʼN', e o
    modificador 'ʼ' passava no isalpha().

    A checagem de comprimento existe porque algumas letras EXPANDEM no
    upper() ('ß' vira 'SS'), e comparar uma string de 2 caracteres contra o
    alfabeto daria falso de qualquer jeito -- mas de forma acidental. Aqui é
    explícito.

    Minúsculas contam como letra da matriz de propósito: a caixa é resolvida
    por _normalizar() antes de cifrar. Fingir que 'd' não é letra faria
    decifrar() devolver o texto intacto em silêncio, escondendo o problema.

    >>> _eh_letra_da_matriz("A"), _eh_letra_da_matriz("J")
    (True, True)
    >>> _eh_letra_da_matriz("ß"), _eh_letra_da_matriz("П"), _eh_letra_da_matriz("!")
    (False, False, False)
    """
    maiuscula = caractere.upper()
    return len(maiuscula) == 1 and (maiuscula in ALFABETO or maiuscula == "J")


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    >>> validar_chave("chave")
    (True, '')
    >>> validar_chave("123")
    (False, 'A chave deve conter ao menos uma letra.')
    """
    letras = [c for c in ascii_puro.normalizar(chave) if _eh_letra_da_matriz(c)]
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
    return ascii_puro.normalizar(texto).upper()


def _extrair_letras(texto_normalizado: str) -> list[str]:
    """
    Só as letras da matriz, na ordem em que aparecem, com J fundido em I.
    Letras de outros alfabetos são ignoradas aqui e tratadas como pontuação
    mais adiante -- ver _eh_letra_da_matriz().

    >>> _extrair_letras("ACAO, JA!")
    ['A', 'C', 'A', 'O', 'I', 'A']
    """
    return [
        "I" if c == "J" else c
        for c in texto_normalizado
        if _eh_letra_da_matriz(c)
    ]


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
      - par com as duas letras iguais -> insere um filler no lugar da
        segunda (X, ou Q quando a letra duplicada é o próprio X);
      - letra sobrando no final (quantidade ímpar) -> completa com X.
    Cada item retornado é (letra_a, a_é_real, letra_b, b_é_real); a
    marcação "é_real" diz se a letra veio do texto original ou se é um
    caractere de preenchimento -- usado depois para saber onde encaixar
    cada letra cifrada na reconstrução da mensagem.

    O preenchimento FINAL é sempre X, nunca Q, e isso importa na hora de
    decifrar: um Q no fim da mensagem é sempre uma letra de verdade
    ("IRAQ"), então nunca precisa ser adivinhado.

    >>> _montar_pares(["H", "E", "L", "L", "O"])
    [('H', True, 'E', True), ('L', True, 'X', False), ('L', True, 'O', True)]
    >>> _montar_pares(["X", "X"])
    [('X', True, 'Q', False), ('X', True, 'X', False)]
    """
    pares = []
    i = 0
    while i < len(letras):
        a = letras[i]
        if i + 1 < len(letras) and letras[i + 1] != a:
            pares.append((a, True, letras[i + 1], True))
            i += 2
        elif i + 1 < len(letras):
            # Duas letras iguais: separa com o filler adequado à letra.
            filler = FILLER_ALTERNATIVO if a == FILLER else FILLER
            pares.append((a, True, filler, False))
            i += 1
        else:
            # Sobrou uma letra no fim: completa sempre com X.
            pares.append((a, True, FILLER, False))
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
        if _eh_letra_da_matriz(c):
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
    Limpeza heurística dos fillers inseridos por cifrar(): remove um
    filler que esteja entre duas letras iguais (LXL -> LL, caso de letra
    duplicada) e remove um X que sobre como última letra da mensagem
    (padding de texto com número ímpar de letras).

    A conta é feita sobre a sequência de LETRAS, ignorando espaços e
    pontuação. A versão anterior comparava os caracteres imediatamente
    vizinhos, e com isso não reconhecia o filler em "L L": o vizinho do X
    era o espaço, não a letra L que o originou, e o X sobrava no texto
    decifrado.

    A posição também entra na conta: um filler é sempre a SEGUNDA letra
    de um par, logo está sempre em índice ímpar da sequência de letras.
    Isso evita remover uma letra real que por acaso caia entre duas
    iguais.

    Só o X é removido no fim da mensagem, nunca o Q -- ver _montar_pares:
    o preenchimento final é sempre X, então uma mensagem terminada em Q
    ("IRAQ") não corre risco.

    Não há garantia absoluta -- se a mensagem original genuinamente
    tivesse um X nessas posições (ex.: terminar em "RAIO X"), ele
    também seria removido por engano. É a mesma ambiguidade que existe
    ao decifrar Playfair manualmente: o filler só se distingue de uma
    letra real pelo contexto.

    >>> "".join(_remover_x_de_preenchimento(list("HELXLO WORLDX")))
    'HELLO WORLD'
    >>> "".join(_remover_x_de_preenchimento(list("LX LX")))
    'L L'
    >>> "".join(_remover_x_de_preenchimento(list("IRAQ")))
    'IRAQ'
    """
    # posicoes[k] = onde a k-ésima letra está na lista original, para
    # devolver espaços e pontuação intactos no fim.
    posicoes = [i for i, c in enumerate(caracteres) if _eh_letra_da_matriz(c)]
    letras = [caracteres[i] for i in posicoes]

    descartar = set()

    # Filler de letra duplicada: índice ímpar, cercado por duas letras
    # iguais que não são ele mesmo.
    for k in range(1, len(letras) - 1, 2):
        if letras[k] in FILLERS and letras[k - 1] == letras[k + 1] != letras[k]:
            descartar.add(posicoes[k])

    # Filler de padding: só existe quando o texto tinha número ímpar de
    # letras, e nesse caso é sempre o X final.
    if letras and letras[-1] == FILLER and posicoes[-1] not in descartar:
        descartar.add(posicoes[-1])

    return [c for i, c in enumerate(caracteres) if i not in descartar]


def decifrar(texto: str, chave: str) -> str:
    """
    O caminho feliz é receber o que cifrar() produziu: maiúsculas, sem
    acento, número par de letras. Mas decifrar() não pode DEPENDER disso.

    No chat, o texto vem da rede: se o outro participante escolheu outra
    cifra, ou a mensagem é de alguém falando outro dialeto, chega aqui
    algo que não saiu deste cifrar(). Antes, minúscula levantava
    ValueError em _localizar() e número ímpar de letras levantava
    StopIteration -- e as duas derrubavam o cliente inteiro, porque a
    thread de recepção não sobrevive a uma exceção. Decifrar lixo tem de
    produzir lixo, não uma queda.

    >>> decifrar("DMYRAN VQCRGE", "PLAYFAIR EXAMPLE")
    'HELLO WORLD'
    >>> decifrar("dmyran vqcrge", "PLAYFAIR EXAMPLE")
    'HELLO WORLD'
    """
    matriz = _montar_matriz(chave)

    # Mesma normalização de cifrar(): é o que permite receber minúscula
    # ou acento sem estourar. _extrair_letras já funde J em I, então
    # nenhuma letra chega em _localizar() sem estar na matriz.
    texto_normalizado = _normalizar(texto)
    letras_cifradas = _extrair_letras(texto_normalizado)

    letras_decifradas = []
    for i in range(0, len(letras_cifradas) - 1, 2):
        pa, pb = _transformar_par(matriz, letras_cifradas[i], letras_cifradas[i + 1], -1)
        letras_decifradas.append(pa)
        letras_decifradas.append(pb)

    # Número ímpar de letras: a última não tem par, e Playfair não sabe
    # decifrar meia dupla. Passa adiante como veio -- o resultado fica
    # errado, o que é honesto, em vez de faltar uma letra no iterador
    # abaixo e estourar StopIteration.
    if len(letras_cifradas) % 2:
        letras_decifradas.append(letras_cifradas[-1])

    resultado = []
    it = iter(letras_decifradas)
    for c in texto_normalizado:
        resultado.append(next(it) if _eh_letra_da_matriz(c) else c)

    return "".join(_remover_x_de_preenchimento(resultado))
