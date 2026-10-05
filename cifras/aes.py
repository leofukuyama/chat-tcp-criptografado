"""
Cifra de bloco AES-128 (Advanced Encryption Standard, FIPS-197), implementada
do zero, sem nenhuma biblioteca de criptografia, seguindo o mesmo padrao
didatico de cifras/des.py.

O AES NAO e' uma rede de Feistel (como o DES): e' uma rede de
SUBSTITUICAO-PERMUTACAO. Em toda rodada o bloco inteiro (16 bytes) e'
transformado, nao so metade dele. Os 16 bytes formam uma matriz 4x4
chamada ESTADO, e cada rodada aplica 4 operacoes:

    SubBytes     -> substitui cada byte pela S-BOX            (confusao)
    ShiftRows    -> desloca as linhas da matriz               (difusao)
    MixColumns   -> mistura os 4 bytes de cada coluna (GF)    (difusao)
    AddRoundKey  -> XOR do estado com a chave da rodada

Parametros do AES-128: bloco de 128 bits (16 bytes), chave de 128 bits
(16 bytes), 10 rodadas, 11 chaves de rodada (w[0]..w[43], 4 palavras cada).

Fluxo completo de um bloco:

    AddRoundKey(chave 0)
    rodadas 1..9 : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    rodada 10    : SubBytes -> ShiftRows ->              AddRoundKey
                   (a ultima rodada NAO tem MixColumns!)

Tudo aqui e' feito BIT A BIT / BYTE A BYTE, de forma visivel:
  - a aritmetica de GF(2^8) (xtime, multiplicacao) usa deslocamentos e XOR
    explicitos, entao da para acompanhar cada produto de hexadecimais;
  - a S-BOX NAO e' uma tabela decorada: e' CALCULADA (inverso multiplicativo
    em GF(2^8) + transformacao afim), do mesmo jeito que o FIPS-197 define;
  - o Rcon tambem e' calculado (dobrando em GF(2^8)), nao digitado.

Duas camadas neste modulo (igual ao des.py):

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
POLINOMIO_REDUCAO = 0x11B  # x^8 + x^4 + x^3 + x + 1  (irredutivel em GF(2))


# ============================================================
# 1. ARITMETICA EM GF(2^8) -- bit a bit
# ============================================================
# No AES cada byte e' um polinomio de grau <= 7 com coeficientes 0/1:
#     0x57 = 0101 0111  ->  x^6 + x^4 + x^2 + x + 1
# - SOMA em GF(2^8) e' XOR (soma de coeficientes modulo 2).
# - MULTIPLICACAO e' multiplicacao de polinomios, reduzida modulo
#   m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B) para o resultado voltar a caber
#   em 8 bits. Multiplicar por x (= 0x02) e' o bloco basico: "xtime".

def _xtime(byte: int) -> int:
    """
    Multiplica por x (0x02) em GF(2^8): desloca 1 bit a esquerda e, se o bit
    7 estava ligado (o resultado teria grau 8), subtrai (XOR) o polinomio de
    reducao -- como o bit 8 some no corte de 8 bits, so sobra XOR com 0x1B.

    >>> hex(_xtime(0x57))   # 0101 0111 -> 1010 1110, sem estouro
    '0xae'
    >>> hex(_xtime(0xae))   # 1010 1110 -> 1 0101 1100, estoura: XOR 0x1B
    '0x47'
    """
    estourou = (byte & 0x80) != 0
    byte = (byte << 1) & 0xFF
    if estourou:
        byte ^= 0x1B
    return byte


def _mult_gf(a: int, b: int) -> int:
    """
    Multiplicacao em GF(2^8), bit a bit ("shift-and-add"): para cada bit
    ligado de `b` (do menos para o mais significativo), soma (XOR) em
    `resultado` o valor atual de `a`; depois `a` e' multiplicado por x.
    Exemplo do FIPS-197 (secao 4.2): 0x57 * 0x13 = 0xFE, pois
    0x13 = 1 + x + x^4 => 0x57 + xtime(0x57) + xtime^4(0x57).

    >>> hex(_mult_gf(0x57, 0x83))
    '0xc1'
    >>> hex(_mult_gf(0x57, 0x13))
    '0xfe'
    """
    resultado = 0
    for _ in range(8):
        if b & 1:
            resultado ^= a
        a = _xtime(a)
        b >>= 1
    return resultado


def _inverso_gf(byte: int) -> int:
    """
    Inverso multiplicativo em GF(2^8): o unico byte `y` com byte * y = 1.
    Por convencao do AES, o inverso de 0 e' 0 (0 nao tem inverso).
    Busca direta entre 1..255 -- clara de ler e roda uma vez so, na carga
    do modulo.
    """
    if byte == 0:
        return 0
    for candidato in range(1, 256):
        if _mult_gf(byte, candidato) == 1:
            return candidato
    raise AssertionError("todo byte nao nulo tem inverso em GF(2^8)")


# ============================================================
# 2. S-BOX E S-BOX INVERSA -- calculadas, nao decoradas
# ============================================================
# SubBytes troca cada byte `b` por S(b), em dois passos (FIPS-197, 5.1.1):
#   (1) b  <- inverso multiplicativo de b em GF(2^8)   (nao-linear)
#   (2) transformacao AFIM, bit a bit:
#         b'_i = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i
#       com indices de bit modulo 8 (i = 0 e' o bit menos significativo)
#       e c = 0x63 (0110 0011).
# O passo (1) da a nao-linearidade; o (2) impede pontos fixos (S(b) != b).

CONSTANTE_AFIM = 0x63


def _bit(byte: int, posicao: int) -> int:
    """Bit `posicao` (0 = menos significativo) de `byte`."""
    return (byte >> posicao) & 1


def _calcular_sbox_byte(byte: int) -> int:
    """S-BOX de um unico byte: inverso em GF(2^8) + transformacao afim."""
    inverso = _inverso_gf(byte)
    resultado = 0
    for i in range(8):
        bit = (
            _bit(inverso, i)
            ^ _bit(inverso, (i + 4) % 8)
            ^ _bit(inverso, (i + 5) % 8)
            ^ _bit(inverso, (i + 6) % 8)
            ^ _bit(inverso, (i + 7) % 8)
            ^ _bit(CONSTANTE_AFIM, i)
        )
        resultado |= bit << i
    return resultado


SBOX = [_calcular_sbox_byte(b) for b in range(256)]

# A S-BOX inversa nao precisa de formula propria: como S e' uma bijecao,
# basta "ler a tabela de tras para frente": se S[b] = v, entao INV[v] = b.
SBOX_INV = [0] * 256
for _entrada, _saida in enumerate(SBOX):
    SBOX_INV[_saida] = _entrada


# ============================================================
# 3. RCON -- constantes de rodada da expansao de chave
# ============================================================
# Rcon[i] = (x^(i-1) em GF(2^8), 0, 0, 0): so o primeiro byte e' diferente
# de zero. Comeca em 0x01 e dobra (xtime) a cada rodada:
#   01 02 04 08 10 20 40 80 1B 36        <- 0x80 * 2 estoura => 0x1B
# (indexado de 1 a 10, como no FIPS-197; a posicao 0 nao e' usada).

def _gerar_rcon() -> list[int]:
    rcon = [0]  # posicao 0 fica vazia para que RCON[i] seja o da rodada i
    valor = 0x01
    for _ in range(NUM_RODADAS):
        rcon.append(valor)
        valor = _xtime(valor)
    return rcon


RCON = _gerar_rcon()


# ============================================================
# 4. ESTADO (matriz 4x4) E UTILITARIOS
# ============================================================
# Os 16 bytes do bloco entram na matriz POR COLUNA (nao por linha):
#
#     bytes:  b0 b1 b2 b3 b4 b5 ... b15            b0 b4 b8  b12
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
    return [SBOX[byte] for byte in palavra]


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
    return [[SBOX[byte] for byte in linha] for linha in estado]


def _inv_sub_bytes(estado: list[list[int]]) -> list[list[int]]:
    return [[SBOX_INV[byte] for byte in linha] for linha in estado]


def _shift_rows(estado: list[list[int]]) -> list[list[int]]:
    """A linha `l` e' rotacionada `l` posicoes a ESQUERDA (linha 0 fica
    parada, linha 1 anda 1, linha 2 anda 2, linha 3 anda 3). Faz cada byte de
    uma coluna ir parar em colunas diferentes -- e' o que espalha a difusao."""
    return [estado[linha][linha:] + estado[linha][:linha] for linha in range(4)]


def _inv_shift_rows(estado: list[list[int]]) -> list[list[int]]:
    """Inversa: a linha `l` e' rotacionada `l` posicoes a DIREITA."""
    return [estado[linha][4 - linha:] + estado[linha][:4 - linha] for linha in range(4)]


# MixColumns multiplica CADA COLUNA do estado (vetor de 4 bytes) por uma
# matriz fixa 4x4, com produtos e somas em GF(2^8) (soma = XOR):
#
#   | s'0 |   | 02 03 01 01 |   | s0 |       s'0 = 02*s0 ^ 03*s1 ^ 01*s2 ^ 01*s3
#   | s'1 | = | 01 02 03 01 | * | s1 |       s'1 = 01*s0 ^ 02*s1 ^ 03*s2 ^ 01*s3
#   | s'2 |   | 01 01 02 03 |   | s2 |       s'2 = 01*s0 ^ 01*s1 ^ 02*s2 ^ 03*s3
#   | s'3 |   | 03 01 01 02 |   | s3 |       s'3 = 03*s0 ^ 01*s1 ^ 01*s2 ^ 02*s3
#
# A inversa usa a matriz inversa (tambem em GF(2^8)):
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
    """Produto matriz x vetor em GF(2^8): cada elemento da saida e' o XOR
    dos 4 produtos (constante da matriz * byte da coluna)."""
    saida = []
    for linha in range(4):
        acumulado = 0
        for k in range(4):
            acumulado ^= _mult_gf(matriz[linha][k], coluna[k])
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
    texto_normalizado = ascii_puro.normalizar(texto)
    dados = ascii_puro.codificar(texto_normalizado)

    if not dados:
        return ""

    w = _expandir_chave(chave_bytes)
    blocos = _dividir_em_blocos(dados)
    cifrado = b"".join(_cifrar_bloco(bloco, w) for bloco in blocos)
    return base64.b64encode(cifrado).decode("ascii")


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
    dados = _base64_decode_tolerante(texto)

    n_blocos_completos = len(dados) // TAMANHO_BLOCO
    decifrado = bytearray()
    for indice in range(n_blocos_completos):
        bloco = dados[indice * TAMANHO_BLOCO:(indice + 1) * TAMANHO_BLOCO]
        decifrado.extend(_decifrar_bloco(bloco, w))

    sem_padding = bytes(decifrado).rstrip(b"\x00")
    return sem_padding.decode("ascii", errors="backslashreplace")
