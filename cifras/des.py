"""
Cifra de bloco DES (Data Encryption Standard), implementada do zero a
partir das tabelas oficiais (FIPS 46-3), seguindo a explicacao de
README-DES.md (slides "Aula 4" da disciplina).

Duas camadas neste modulo:

  1. MOTOR DES (funcoes privadas com prefixo "_", ex.: _cifrar_bloco):
     operam sobre BYTES CRUS (0-255), sem nenhuma restricao de charset.
     E' contra essas funcoes que os vetores de teste classicos do DES sao
     validados -- varios deles tem bytes fora do intervalo ASCII (ex.: a
     chave de exemplo do PDF, 01 23 45 67 89 AB CD EF, tem bytes como
     0x89 e 0xAB que nunca poderiam ser digitados como texto no chat).

  2. CONTRATO DO CHAT (validar_chave/cifrar/decifrar/bytes_brutos):
     e' o que cifras/registro.py e client.py enxergam. Aqui a chave e'
     uma senha em ASCII (igual as outras 5 cifras do catalogo), com no
     maximo 8 caracteres -- completada com zeros a direita se for mais
     curta, exatamente como o professor autorizou preencher com zero
     qualquer coisa que precise fechar em 64 bits.

Bloco e chave do DES tem sempre 64 bits (8 bytes). Chave efetiva e' de 56
bits -- os outros 8 sao descartados pela PC-1 (bits de paridade).
"""

import base64
import binascii

import ascii_puro

TAMANHO_BLOCO = 8  # bytes = 64 bits


# ============================================================
# TABELAS FIXAS (FIPS 46-3) -- todas 1-indexadas: a posicao i do
# resultado de uma permutacao vem do bit `tabela[i]` (contando do 1) da
# entrada. Transcritas de README-DES.md / slides da disciplina.
# ============================================================

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E_TABELA = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P_TABELA = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

DESLOCAMENTOS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

S_BOXES = [
    [  # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [  # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [  # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [  # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [  # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [  # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [  # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [  # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


# ============================================================
# UTILITARIOS DE BITS
# ============================================================

def _bytes_para_bits(dados: bytes) -> list[int]:
    """Cada byte vira 8 bits, MSB primeiro -- e' essa convencao que faz o
    bit 1 da tabela (1-indexada) corresponder ao bit mais significativo
    do primeiro byte, igual a especificacao original do DES."""
    bits = []
    for byte in dados:
        for deslocamento in range(7, -1, -1):
            bits.append((byte >> deslocamento) & 1)
    return bits


def _bits_para_bytes(bits: list[int]) -> bytes:
    resultado = bytearray()
    for inicio in range(0, len(bits), 8):
        byte = 0
        for bit in bits[inicio:inicio + 8]:
            byte = (byte << 1) | bit
        resultado.append(byte)
    return bytes(resultado)


def _permutar(bits: list[int], tabela: list[int]) -> list[int]:
    """Tabela 1-indexada: saida[i] = bits[tabela[i] - 1]."""
    return [bits[posicao - 1] for posicao in tabela]


def _deslocar_esquerda(bits: list[int], quantidade: int) -> list[int]:
    quantidade = quantidade % len(bits)
    return bits[quantidade:] + bits[:quantidade]


def _xor(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


# ============================================================
# GERACAO DAS 16 SUBCHAVES
# ============================================================

def _gerar_subchaves(chave_bytes: bytes) -> list[list[int]]:
    """
    A partir da chave de 64 bits (8 bytes), gera as 16 subchaves de 48
    bits usadas em cada rodada -- PC-1 (64->56 bits), divide em C0/D0
    (28 bits cada), aplica os deslocamentos circulares a esquerda por
    rodada e concatena+permuta com PC-2 (56->48 bits). Ver README-DES.md
    secao 5 para o passo a passo com o exemplo numerico dos slides.
    """
    bits_chave = _bytes_para_bits(chave_bytes)
    chave_56 = _permutar(bits_chave, PC1)
    c = chave_56[:28]
    d = chave_56[28:]

    subchaves = []
    for deslocamento in DESLOCAMENTOS:
        c = _deslocar_esquerda(c, deslocamento)
        d = _deslocar_esquerda(d, deslocamento)
        subchaves.append(_permutar(c + d, PC2))
    return subchaves


# ============================================================
# FUNCAO DE FEISTEL (F)
# ============================================================

def _expandir(bits_r: list[int]) -> list[int]:
    """Expande R de 32 para 48 bits (tabela E) -- alguns bits de borda de
    cada grupo de 4 aparecem repetidos em dois grupos adjacentes, e' o
    que permite fazer XOR com a subchave de 48 bits."""
    return _permutar(bits_r, E_TABELA)


def _substituir_sbox(bits48: list[int]) -> list[int]:
    """Reduz 48 bits para 32 usando as 8 S-BOX: cada grupo de 6 bits vira
    4 -- primeiro e ultimo bit do grupo formam a linha (0-3), os 4 bits
    do meio formam a coluna (0-15)."""
    saida = []
    for indice_caixa in range(8):
        grupo = bits48[indice_caixa * 6:(indice_caixa + 1) * 6]
        linha = grupo[0] * 2 + grupo[5]
        coluna = grupo[1] * 8 + grupo[2] * 4 + grupo[3] * 2 + grupo[4]
        valor = S_BOXES[indice_caixa][linha][coluna]
        saida.extend([(valor >> 3) & 1, (valor >> 2) & 1, (valor >> 1) & 1, valor & 1])
    return saida


def _funcao_f(bits_r: list[int], subchave: list[int]) -> list[int]:
    """Funcao F de uma rodada de Feistel: expande R (32->48), XOR com a
    subchave da rodada, substitui pelas 8 S-BOX (48->32) e permuta com a
    tabela P. Devolve 32 bits."""
    expandido = _expandir(bits_r)
    resultado_xor = _xor(expandido, subchave)
    saida_sbox = _substituir_sbox(resultado_xor)
    return _permutar(saida_sbox, P_TABELA)
