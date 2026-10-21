"""
Cifra de bloco AES-128 (Advanced Encryption Standard, FIPS-197), implementada
do zero, sem nenhuma biblioteca de criptografia, seguindo passo a passo o que
foi visto na aula (slides "AES") e no mesmo estilo didatico das demais cifras.

O AES NAO e' uma rede de Feistel (como o DES): e' uma rede de
SUBSTITUICAO-PERMUTACAO. Em toda rodada o bloco inteiro (16 bytes) e'
transformado, nao so metade dele. Os 16 bytes formam uma matriz 4x4
chamada ESTADO, e cada rodada aplica 4 operacoes:

    SubBytes     -> substitui cada byte pela S-BOX            (confusao)
    ShiftRows    -> desloca as linhas da matriz               (difusao)
    MixColumns   -> mistura os 4 bytes de cada coluna         (difusao)
    AddRoundKey  -> XOR do estado com a chave da rodada

Parametros do AES-128: bloco de 128 bits (16 bytes), chave de 128 bits
(16 bytes), 10 rodadas, 11 chaves de rodada (w[0]..w[43], 4 palavras cada).

Fluxo completo de um bloco:

    AddRoundKey(chave 0)
    rodadas 1..9 : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    rodada 10    : SubBytes -> ShiftRows ->               AddRoundKey
                   (a ultima rodada NAO tem MixColumns!)

Tudo aqui usa so as ferramentas apresentadas na aula:
  - SubBytes e' uma BUSCA NA TABELA S-box (o digito hexadecimal da esquerda
    escolhe a linha, o da direita escolhe a coluna); InvSubBytes faz o mesmo
    na S-box inversa;
  - MixColumns e InvMixColumns multiplicam bytes so com DESLOCAMENTO e XOR:
    multiplicar por 02 e' deslocar 1 bit e, se o primeiro bit era 1, fazer XOR
    com 1B; as outras constantes (03, 09, 0B, 0D, 0E) somam por XOR os multiplos
    01, 02, 04 e 08 do byte que os bits da constante selecionam;
  - a expansao de chave usa RotWord, SubWord (a mesma S-box) e Rcon, com o
    Rcon na tabela 01 02 04 08 10 20 40 80 1B 36.

Duas camadas neste modulo:

  1. MOTOR AES (funcoes privadas com prefixo "_"): operam sobre BYTES CRUS
     (0-255). E' contra elas que os vetores oficiais do FIPS-197 sao
     validados -- muitos tem bytes acima de 0x7F.
  2. CONTRATO DO CHAT (validar_chave/cifrar/decifrar/bytes_brutos): o que
     cifras/registro.py e client.py enxergam. A chave aceita dois formatos
     que nunca se confundem:
       - senha ASCII de ate 16 caracteres (completada com zeros a direita);
       - 32 digitos hexadecimais (espacos opcionais), ex.:
         "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c".
     O texto e' dividido em blocos de 16 bytes (modo ECB, ultimo bloco
     completado com zeros) e o criptograma trafega em Base64.

Conferencia manual: https://simewu.com/aes/ (AES-128, modo ECB, entrada e
saida em hexadecimal -- use a chave hexadecimal do chat para obter o mesmo
criptograma, que o chat tambem exibe em hexadecimal).
"""

import base64
import binascii

import ascii_puro

TAMANHO_BLOCO = 16   # bytes = 128 bits
TAMANHO_CHAVE = 16   # bytes = 128 bits  -> AES-128
NUM_RODADAS = 10     # Nr: 10 rodadas para chave de 128 bits
NUM_COLUNAS = 4      # Nb: o estado tem sempre 4 colunas (4 palavras)


# ============================================================
# 1. MULTIPLICACAO DE BYTES (campo de Galois GF(2^8), como na aula)
# ============================================================
# O MixColumns e o InvMixColumns multiplicam bytes por constantes de uma
# matriz fixa. Nesse "campo de Galois":
#   - a SOMA e' o XOR bit a bit;
#   - a MULTIPLICACAO usa so deslocamento de bits e XOR, como nos slides.
#
# MULTIPLICAR POR 02: desloca o byte 1 bit a esquerda. Se o primeiro bit
# (bit 7) do byte ORIGINAL era 1, descarta o 9o bit e faz XOR com 1B
# (0001 1011) -- a "correcao":
#     02 x 47:  0100 0111 -> 1000 1110 = 8E             (primeiro bit 0: sem correcao)
#     02 x 8E:  1000 1110 -> 1 0001 1100 -> 1C; 1C XOR 1B = 07   (primeiro bit 1)
#
# MULTIPLICAR POR OUTRA CONSTANTE: calculam-se os multiplos 01, 02, 04 e 08
# do byte (cada um e' o anterior vezes 02) e faz-se XOR so dos multiplos cujo
# bit esta ligado na constante:
#     03 = 0000 0011 -> 02 e 01           03 x B = (02 x B) XOR B
#     0E = 0000 1110 -> 08, 04 e 02       0B = 0000 1011 -> 08, 02 e 01
#     0D = 0000 1101 -> 08, 04 e 01       09 = 0000 1001 -> 08 e 01

def _multiplicar_por_2(byte: int) -> int:
    """
    Multiplica o byte por 02: desloca 1 bit a esquerda e, se o primeiro bit
    do byte original era 1, faz XOR com 1B.

    >>> hex(_multiplicar_por_2(0x47))   # 0100 0111 -> 1000 1110
    '0x8e'
    >>> hex(_multiplicar_por_2(0x8E))   # primeiro bit 1: 1C XOR 1B
    '0x7'
    """
    deslocado = (byte << 1) & 0xFF   # o 9o bit e' descartado
    if byte & 0x80:                  # o primeiro bit do byte original era 1?
        deslocado ^= 0x1B
    return deslocado


def _multiplicar(constante: int, byte: int) -> int:
    """
    Multiplica o byte por uma constante de 4 bits (as das matrizes do
    MixColumns e do InvMixColumns: 01, 02, 03, 09, 0B, 0D e 0E): XOR dos
    multiplos 01, 02, 04 e 08 do byte que a constante seleciona pelos seus bits.

    >>> hex(_multiplicar(0x03, 0x6E))   # (6E x 02) XOR 6E = DC XOR 6E
    '0xb2'
    >>> hex(_multiplicar(0x0E, 0x47))   # 08x47 XOR 04x47 XOR 02x47 = 0E XOR 07 XOR 8E
    '0x87'
    """
    if not 0 <= constante <= 0x0F:
        raise ValueError("A constante deve caber em 4 bits (de 00 a 0F).")

    multiplo_01 = byte
    multiplo_02 = _multiplicar_por_2(multiplo_01)
    multiplo_04 = _multiplicar_por_2(multiplo_02)
    multiplo_08 = _multiplicar_por_2(multiplo_04)

    resultado = 0
    if constante & 0x01:
        resultado ^= multiplo_01
    if constante & 0x02:
        resultado ^= multiplo_02
    if constante & 0x04:
        resultado ^= multiplo_04
    if constante & 0x08:
        resultado ^= multiplo_08
    return resultado


# ============================================================
# 2. S-BOX E S-BOX INVERSA (tabelas dos slides)
# ============================================================
# O SubBytes troca cada byte do estado pelo valor encontrado na tabela S-box:
#   - o digito hexadecimal da ESQUERDA do byte escolhe a LINHA;
#   - o digito hexadecimal da DIREITA do byte escolhe a COLUNA.
# Exemplo: o byte 53 -> linha 5, coluna 3 -> SBOX[5][3] = ED.
# O InvSubBytes faz a mesma busca na S-box INVERSA (SBOX_INV[0xE][0xD] = 53).
# Tabelas 5.2(a) e 5.2(b) dos slides.

#    0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
SBOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],  # linha 0
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],  # linha 1
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],  # linha 2
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],  # linha 3
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],  # linha 4
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],  # linha 5
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],  # linha 6
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],  # linha 7
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],  # linha 8
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],  # linha 9
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],  # linha A
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],  # linha B
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],  # linha C
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],  # linha D
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],  # linha E
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],  # linha F
]

#    0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
SBOX_INV = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],  # linha 0
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],  # linha 1
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],  # linha 2
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],  # linha 3
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],  # linha 4
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],  # linha 5
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],  # linha 6
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],  # linha 7
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],  # linha 8
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],  # linha 9
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],  # linha A
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],  # linha B
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],  # linha C
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],  # linha D
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],  # linha E
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D],  # linha F
]


def _substituir_byte(byte: int, tabela: list[list[int]]) -> int:
    """
    Busca o byte na tabela: digito hexadecimal da esquerda = linha, digito
    hexadecimal da direita = coluna.

    >>> hex(_substituir_byte(0x53, SBOX))
    '0xed'
    >>> hex(_substituir_byte(0xED, SBOX_INV))
    '0x53'
    """
    linha = byte >> 4        # digito da esquerda (os 4 bits de cima)
    coluna = byte & 0x0F     # digito da direita (os 4 bits de baixo)
    return tabela[linha][coluna]


# ============================================================
# 3. RCON -- constantes de rodada da expansao de chave
# ============================================================
# Rcon[j] = (RC_j, 00, 00, 00): so o primeiro byte e' diferente de zero. Os
# valores de RC_j sao os da tabela dos slides (rodada j = 1 a 10):
#   Rcon(1)=01  Rcon(2)=02  Rcon(3)=04  Rcon(4)=08  Rcon(5)=10
#   Rcon(6)=20  Rcon(7)=40  Rcon(8)=80  Rcon(9)=1B  Rcon(10)=36
# A posicao 0 nao e' usada: assim RCON[j] e' o da rodada j.

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ============================================================
# 4. ESTADO (matriz 4x4) E UTILITARIOS
# ============================================================
# Os 16 bytes do bloco entram na matriz POR COLUNA (nao por linha):
#
#     bytes:  b0 b1 b2 b3 b4 b5 ... b15                    b0 b4 b8  b12
#     estado[linha][coluna]  =  bloco[linha + 4*coluna]    b1 b5 b9  b13
#                                                          b2 b6 b10 b14
#                                                          b3 b7 b11 b15
# Cada coluna do estado e' uma "palavra" w de 4 bytes.

def _bytes_para_estado(bloco: bytes) -> list[list[int]]:
    return [[bloco[linha + 4 * coluna] for coluna in range(4)] for linha in range(4)]


def _estado_para_bytes(estado: list[list[int]]) -> bytes:
    return bytes(estado[linha][coluna] for coluna in range(4) for linha in range(4))


def _xor_bytes(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


# ============================================================
# 5. EXPANSAO DE CHAVE (w[0]..w[43])
# ============================================================
# A chave de 16 bytes vira 44 palavras de 4 bytes (w[0]..w[43]) = 11 chaves
# de rodada de 4 palavras cada (a rodada r usa w[4r]..w[4r+3]):
#
#   w[0..3]  = a propria chave, 4 bytes por palavra
#   para i = 4..43:
#       temp = w[i-1]
#       se i e' multiplo de 4:                 (primeira palavra de cada chave)
#           temp = SubWord( RotWord(temp) ) XOR (Rcon[i/4], 0, 0, 0)
#       w[i] = w[i-4] XOR temp
#
#   RotWord: rotaciona a palavra 1 byte a esquerda   [a0 a1 a2 a3] -> [a1 a2 a3 a0]
#   SubWord: aplica a S-BOX a cada byte da palavra

def _rot_word(palavra: list[int]) -> list[int]:
    return palavra[1:] + palavra[:1]


def _sub_word(palavra: list[int]) -> list[int]:
    return [_substituir_byte(byte, SBOX) for byte in palavra]


def _expandir_chave(chave: bytes) -> list[list[int]]:
    """Devolve as 44 palavras w[0]..w[43] (cada uma, lista de 4 bytes)."""
    if len(chave) != TAMANHO_CHAVE:
        raise ValueError(f"A chave AES-128 deve ter exatamente {TAMANHO_CHAVE} bytes.")

    w = [list(chave[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, NUM_COLUNAS * (NUM_RODADAS + 1)):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // 4]
        w.append(_xor_bytes(w[i - 4], temp))
    return w


def _chave_da_rodada(w: list[list[int]], rodada: int) -> list[list[int]]:
    """Chave da rodada como matriz 4x4: a coluna c e' a palavra w[4*rodada + c]."""
    return [[w[4 * rodada + coluna][linha] for coluna in range(4)] for linha in range(4)]


# ============================================================
# 6. AS 4 OPERACOES DA RODADA E SUAS INVERSAS
# ============================================================

def _add_round_key(estado: list[list[int]], chave_rodada: list[list[int]]) -> list[list[int]]:
    """XOR byte a byte do estado com a chave da rodada. E' a propria inversa
    (XOR duas vezes com o mesmo valor devolve o original)."""
    return [_xor_bytes(estado[linha], chave_rodada[linha]) for linha in range(4)]


def _sub_bytes(estado: list[list[int]]) -> list[list[int]]:
    """Cada byte do estado e' trocado pelo valor da tabela S-box."""
    return [[_substituir_byte(byte, SBOX) for byte in linha] for linha in estado]


def _inv_sub_bytes(estado: list[list[int]]) -> list[list[int]]:
    """Cada byte do estado e' trocado pelo valor da tabela S-box inversa."""
    return [[_substituir_byte(byte, SBOX_INV) for byte in linha] for linha in estado]


def _shift_rows(estado: list[list[int]]) -> list[list[int]]:
    """A linha `l` e' rotacionada `l` posicoes a ESQUERDA (linha 0 fica
    parada, linha 1 anda 1, linha 2 anda 2, linha 3 anda 3). Faz cada byte de
    uma coluna ir parar em colunas diferentes -- e' o que espalha a difusao."""
    return [estado[linha][linha:] + estado[linha][:linha] for linha in range(4)]


def _inv_shift_rows(estado: list[list[int]]) -> list[list[int]]:
    """Inversa: a linha `l` e' rotacionada `l` posicoes a DIREITA."""
    return [estado[linha][4 - linha:] + estado[linha][:4 - linha] for linha in range(4)]


# MixColumns multiplica CADA COLUNA do estado (vetor de 4 bytes) pela matriz
# fixa 4x4 dos slides. Cada byte da saida e' o XOR de 4 produtos, calculados
# com a multiplicacao da secao 1 (deslocar e XOR):
#
#   | s'0 |   | 02 03 01 01 |   | s0 |       s'0 = 02*s0 ^ 03*s1 ^ 01*s2 ^ 01*s3
#   | s'1 | = | 01 02 03 01 | * | s1 |       s'1 = 01*s0 ^ 02*s1 ^ 03*s2 ^ 01*s3
#   | s'2 |   | 01 01 02 03 |   | s2 |       s'2 = 01*s0 ^ 01*s1 ^ 02*s2 ^ 03*s3
#   | s'3 |   | 03 01 01 02 |   | s3 |       s'3 = 03*s0 ^ 01*s1 ^ 01*s2 ^ 02*s3
#
# O InvMixColumns usa a matriz inversa dos slides, do mesmo jeito (as
# constantes 0E, 0B, 0D e 09 usam os multiplos 08, 04, 02 e 01 do byte):
#   | 0E 0B 0D 09 |
#   | 09 0E 0B 0D |
#   | 0D 09 0E 0B |
#   | 0B 0D 09 0E |

MATRIZ_MIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
]

MATRIZ_MIX_INV = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E],
]


def _multiplicar_coluna(matriz: list[list[int]], coluna: list[int]) -> list[int]:
    """Matriz fixa x coluna: cada byte da saida e' o XOR dos 4 produtos
    (constante da linha da matriz x byte da coluna), com a multiplicacao da
    secao 1. Exemplo dos slides, coluna 87 6E 46 A6, primeira linha:
    (2*87) XOR (3*6E) XOR 46 XOR A6 = 15 XOR B2 XOR 46 XOR A6 = 47."""
    saida = []
    for linha in range(4):
        acumulado = 0
        for k in range(4):
            acumulado ^= _multiplicar(matriz[linha][k], coluna[k])
        saida.append(acumulado)
    return saida


def _aplicar_matriz_nas_colunas(matriz: list[list[int]], estado: list[list[int]]) -> list[list[int]]:
    novo = [[0] * 4 for _ in range(4)]
    for coluna in range(4):
        entrada = [estado[linha][coluna] for linha in range(4)]
        saida = _multiplicar_coluna(matriz, entrada)
        for linha in range(4):
            novo[linha][coluna] = saida[linha]
    return novo


def _mix_columns(estado: list[list[int]]) -> list[list[int]]:
    return _aplicar_matriz_nas_colunas(MATRIZ_MIX, estado)


def _inv_mix_columns(estado: list[list[int]]) -> list[list[int]]:
    return _aplicar_matriz_nas_colunas(MATRIZ_MIX_INV, estado)


# ============================================================
# 7. CIFRA/DECIFRA DE UM BLOCO DE 128 BITS
# ============================================================

def _registrar(rastro: list | None, nome: str, estado: list[list[int]]) -> None:
    """Se um `rastro` (lista) foi passado, guarda (nome, estado em hex) --
    usado pelos testes e para depurar/ensinar rodada a rodada."""
    if rastro is not None:
        rastro.append((nome, _estado_para_bytes(estado).hex()))


def _cifrar_bloco(bloco: bytes, w: list[list[int]], rastro: list | None = None) -> bytes:
    """
    Cifra um bloco de 16 bytes. `w` vem de _expandir_chave().

        AddRoundKey(0)
        rodadas 1..9 : SubBytes, ShiftRows, MixColumns, AddRoundKey(r)
        rodada 10    : SubBytes, ShiftRows,             AddRoundKey(10)
    """
    estado = _bytes_para_estado(bloco)
    _registrar(rastro, "entrada", estado)

    estado = _add_round_key(estado, _chave_da_rodada(w, 0))
    _registrar(rastro, "r0.add_round_key", estado)

    for rodada in range(1, NUM_RODADAS):
        estado = _sub_bytes(estado)
        _registrar(rastro, f"r{rodada}.sub_bytes", estado)
        estado = _shift_rows(estado)
        _registrar(rastro, f"r{rodada}.shift_rows", estado)
        estado = _mix_columns(estado)
        _registrar(rastro, f"r{rodada}.mix_columns", estado)
        estado = _add_round_key(estado, _chave_da_rodada(w, rodada))
        _registrar(rastro, f"r{rodada}.add_round_key", estado)

    # Rodada final: IGUAL as anteriores, mas SEM MixColumns.
    estado = _sub_bytes(estado)
    _registrar(rastro, f"r{NUM_RODADAS}.sub_bytes", estado)
    estado = _shift_rows(estado)
    _registrar(rastro, f"r{NUM_RODADAS}.shift_rows", estado)
    estado = _add_round_key(estado, _chave_da_rodada(w, NUM_RODADAS))
    _registrar(rastro, f"r{NUM_RODADAS}.add_round_key", estado)

    return _estado_para_bytes(estado)


def _decifrar_bloco(bloco: bytes, w: list[list[int]], rastro: list | None = None) -> bytes:
    """
    Decifra um bloco de 16 bytes desfazendo a cifracao NA ORDEM INVERSA e
    com as chaves de rodada de tras para frente (10, 9, ..., 0):

        AddRoundKey(10)
        rodadas 9..1 : InvShiftRows, InvSubBytes, AddRoundKey(r), InvMixColumns
        rodada final : InvShiftRows, InvSubBytes, AddRoundKey(0)

    Cuidado classico: o InvMixColumns vem DEPOIS do AddRoundKey (e nao antes
    como na cifracao) e nao existe na ultima etapa -- espelho exato de
    "a rodada 10 da cifracao nao tem MixColumns".
    """
    estado = _bytes_para_estado(bloco)
    _registrar(rastro, "entrada", estado)

    estado = _add_round_key(estado, _chave_da_rodada(w, NUM_RODADAS))
    _registrar(rastro, f"r{NUM_RODADAS}.add_round_key", estado)

    for rodada in range(NUM_RODADAS - 1, 0, -1):
        estado = _inv_shift_rows(estado)
        _registrar(rastro, f"r{rodada}.inv_shift_rows", estado)
        estado = _inv_sub_bytes(estado)
        _registrar(rastro, f"r{rodada}.inv_sub_bytes", estado)
        estado = _add_round_key(estado, _chave_da_rodada(w, rodada))
        _registrar(rastro, f"r{rodada}.add_round_key", estado)
        estado = _inv_mix_columns(estado)
        _registrar(rastro, f"r{rodada}.inv_mix_columns", estado)

    estado = _inv_shift_rows(estado)
    _registrar(rastro, "r0.inv_shift_rows", estado)
    estado = _inv_sub_bytes(estado)
    _registrar(rastro, "r0.inv_sub_bytes", estado)
    estado = _add_round_key(estado, _chave_da_rodada(w, 0))
    _registrar(rastro, "r0.add_round_key", estado)

    return _estado_para_bytes(estado)


# ============================================================
# CONTRATO DO CHAT (ASCII na entrada, Base64 na saida)
# ============================================================

def _chave_hexadecimal(chave: str) -> bytes | None:
    """
    Se a chave for exatamente 32 digitos hexadecimais (espacos ignorados),
    devolve os 16 bytes correspondentes; senao, None.

    >>> _chave_hexadecimal("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c").hex()
    '2b7e151628aed2a6abf7158809cf4f3c'
    >>> _chave_hexadecimal("Senha123") is None
    True
    """
    digitos = "".join(chave.split())
    if len(digitos) != 2 * TAMANHO_CHAVE:
        return None
    if any(c not in "0123456789abcdefABCDEF" for c in digitos):
        return None
    return bytes.fromhex(digitos)


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    Aceita 32 digitos hexadecimais (ver _chave_hexadecimal) ou uma senha:
    nao vazia, ASCII puro apos normalizar acento, no maximo TAMANHO_CHAVE
    (16) caracteres -- o AES-128 usa chave de 128 bits e uma senha maior nao
    caberia sem truncar em silencio.

    >>> validar_chave("Senha123")
    (True, '')
    >>> validar_chave("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
    (True, '')
    >>> validar_chave("")
    (False, 'A chave não pode ser vazia.')
    """
    if _chave_hexadecimal(chave) is not None:
        return True, ""

    chave_normalizada = ascii_puro.normalizar(chave)

    if not chave_normalizada:
        return False, "A chave não pode ser vazia."

    valida, erro = ascii_puro.validar(chave_normalizada)
    if not valida:
        return False, f"A chave deve conter apenas caracteres ASCII ({erro})."

    if len(chave_normalizada) > TAMANHO_CHAVE:
        return False, (
            f"A chave deve ter no máximo {TAMANHO_CHAVE} caracteres ou exatamente "
            f"{2 * TAMANHO_CHAVE} dígitos hexadecimais "
            "(ex.: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c)."
        )

    return True, ""


def _preparar_chave(chave: str) -> bytes:
    """
    Valida e converte a chave para exatamente 16 bytes: chave hexadecimal
    vira os bytes crus; senha ASCII e' completada com zeros a direita se
    for mais curta (mesmo padding autorizado pelo professor, igual ao DES).

    >>> _preparar_chave("ab")
    b'ab\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
    """
    valida, erro = validar_chave(chave)
    if not valida:
        raise ValueError(erro)
    chave_hex = _chave_hexadecimal(chave)
    if chave_hex is not None:
        return chave_hex
    chave_bytes = ascii_puro.normalizar(chave).encode("ascii")
    return chave_bytes.ljust(TAMANHO_CHAVE, b"\x00")


def _dividir_em_blocos(dados: bytes) -> list[bytes]:
    """Divide em blocos de TAMANHO_BLOCO bytes, completando o ultimo com
    zeros se necessario (padding simples, autorizado pelo professor)."""
    resto = len(dados) % TAMANHO_BLOCO
    if resto != 0:
        dados = dados + b"\x00" * (TAMANHO_BLOCO - resto)
    return [dados[i:i + TAMANHO_BLOCO] for i in range(0, len(dados), TAMANHO_BLOCO)]


def cifrar(texto: str, chave: str) -> str:
    """
    Cifra um texto usando AES-128 em modo ECB (cada bloco de 16 bytes
    cifrado independentemente com as mesmas chaves de rodada) e devolve o
    criptograma em Base64 -- o criptograma bruto tem bytes 0-255,
    incompativel com a regra ASCII-only da rede deste projeto.

    >>> cifrar("", "Senha123")
    ''
    """
    chave_bytes = _preparar_chave(chave)
    modo_hex = texto.lower().startswith("hex:")

    if modo_hex:
        texto_hex = texto[4:].replace(" ", "")
        dados = bytes.fromhex(texto_hex)
    else:
        texto_normalizado = ascii_puro.normalizar(texto)
        dados = ascii_puro.codificar(texto_normalizado)

    if not dados:
        return ""

    w = _expandir_chave(chave_bytes)
    blocos = _dividir_em_blocos(dados)
    cifrado = b"".join(_cifrar_bloco(bloco, w) for bloco in blocos)

    resultado = base64.b64encode(cifrado).decode("ascii")

    return "H:" + resultado if modo_hex else resultado


def _base64_decode_tolerante(texto: str) -> bytes:
    """
    Decodifica Base64 sem nunca lancar excecao -- mesma logica de
    des/rc4._base64_decode_tolerante, duplicada aqui para manter cada
    modulo de cifra autocontido (o padrao do projeto e' nao importar entre
    modulos irmaos, so de ascii_puro).
    """
    texto_ascii = texto.encode("ascii", errors="ignore").decode("ascii")
    texto_com_padding = texto_ascii + "=" * (-len(texto_ascii) % 4)
    try:
        return base64.b64decode(texto_com_padding, validate=False)
    except binascii.Error:
        return texto_ascii.encode("ascii", errors="ignore")


def bytes_brutos(texto_cifrado: str) -> bytes:
    """
    Extensao OPCIONAL do contrato das cifras (ver cifras/rc4.py): expoe o
    criptograma decodificado do Base64 para client.py exibir
    "[CIFRADO decimal]" e "[CIFRADO hexadecimal]", como no RC4 e no DES.
    """
    if texto_cifrado.startswith("H:"):
        texto_cifrado = texto_cifrado[2:]

    return _base64_decode_tolerante(texto_cifrado)


def decifrar(texto: str, chave: str) -> str:
    """
    Decifra um criptograma em Base64 de volta ao texto original. Nunca
    lanca excecao (client.py chama isso direto na thread de recepcao, sem
    try/except): Base64 invalido produz poucos ou nenhum bloco completo, e
    chave errada produz bytes que decodificam como lixo via
    errors="backslashreplace" -- igual ao des/rc4.decifrar().

    Limitacao aceita: o padding usa zeros a direita (rstrip(b"\\x00")),
    entao um texto original que termine com byte(s) NUL de verdade seria
    removido junto -- inatingivel pelo chat, ja que input() nunca produz
    NUL embutido.

    >>> decifrar(cifrar("Ola mundo!", "Senha123"), "Senha123")
    'Ola mundo!'
    """
    chave_bytes = _preparar_chave(chave)
    w = _expandir_chave(chave_bytes)

    modo_hex = texto.startswith("H:")

    if modo_hex:
        texto = texto[2:]

    dados = _base64_decode_tolerante(texto)

    n_blocos_completos = len(dados) // TAMANHO_BLOCO
    decifrado = bytearray()
    for indice in range(n_blocos_completos):
        bloco = dados[indice * TAMANHO_BLOCO:(indice + 1) * TAMANHO_BLOCO]
        decifrado.extend(_decifrar_bloco(bloco, w))

        if modo_hex:
            return bytes(decifrado).hex().upper()

    sem_padding = bytes(decifrado).rstrip(b"\x00")
    return sem_padding.decode("ascii", errors="backslashreplace")
