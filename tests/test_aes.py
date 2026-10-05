"""
Testes isolados da Cifra AES-128 -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_aes.py  (a partir da raiz do projeto)

Os vetores vem do FIPS-197 (o documento oficial do AES):
  - Apendice A.1: expansao da chave 2b7e1516 28aed2a6 abf71588 09cf4f3c
  - Apendice B:   cifragem de 3243f6a8 885a308d 313198a2 e0370734, com o
                  estado depois de cada etapa das rodadas
  - Apendice C.1: chave 000102...0f, texto claro 00112233...ff
Alem deles, ha testes dirigidos aos erros mais comuns ao implementar o
AES (ver teste_erro_* e teste_rastro_*).
"""

import base64
import os
import random
import re
import sys

# Garante que o pacote cifras/ seja encontrado mesmo rodando este arquivo
# diretamente de dentro da pasta tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import aes

# --- Vetores do FIPS-197 ---------------------------------------------------
CHAVE_A1 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")      # Apendice A.1 / B
CLARO_B = bytes.fromhex("3243f6a8885a308d313198a2e0370734")       # Apendice B
CIFRADO_B = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")     # Apendice B

CHAVE_C1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")      # Apendice C.1
CLARO_C1 = bytes.fromhex("00112233445566778899aabbccddeeff")
CIFRADO_C1 = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


def _palavra_hex(palavra: list[int]) -> str:
    return bytes(palavra).hex()


# ============================================================
# GF(2^8): XTIME E MULTIPLICACAO
# ============================================================

def teste_xtime_exemplos_do_fips():
    # FIPS-197 secao 4.2.1: 57 -> AE -> 47 -> 8E -> 07 (so o 2o estoura).
    assert aes._xtime(0x57) == 0xAE
    assert aes._xtime(0xAE) == 0x47
    assert aes._xtime(0x47) == 0x8E
    assert aes._xtime(0x8E) == 0x07


def teste_xtime_so_estoura_com_bit_7():
    # Sem bit 7: e' um deslocamento puro. Com bit 7: desloca e XOR 0x1B.
    assert aes._xtime(0x7F) == 0xFE
    assert aes._xtime(0x80) == 0x1B
    assert aes._xtime(0xFF) == 0xE5


def teste_mult_gf_exemplos_do_fips():
    assert aes._mult_gf(0x57, 0x83) == 0xC1   # FIPS-197 secao 4.2
    assert aes._mult_gf(0x57, 0x13) == 0xFE   # FIPS-197 secao 4.2.1


def teste_mult_gf_propriedades():
    for a in range(256):
        assert aes._mult_gf(a, 0) == 0
        assert aes._mult_gf(a, 1) == a
        assert aes._mult_gf(a, 2) == aes._xtime(a)
    rng = random.Random(1)
    for _ in range(300):
        a, b, c = rng.randrange(256), rng.randrange(256), rng.randrange(256)
        assert aes._mult_gf(a, b) == aes._mult_gf(b, a)                       # comutativa
        assert aes._mult_gf(a, b ^ c) == aes._mult_gf(a, b) ^ aes._mult_gf(a, c)  # distributiva


def teste_inverso_gf():
    assert aes._inverso_gf(0) == 0          # convencao do AES
    assert aes._inverso_gf(0x53) == 0xCA    # FIPS-197 secao 5.1.1
    for byte in range(1, 256):
        assert aes._mult_gf(byte, aes._inverso_gf(byte)) == 1, hex(byte)


# ============================================================
# S-BOX E RCON
# ============================================================

def teste_sbox_valores_conhecidos():
    assert aes.SBOX[0x00] == 0x63
    assert aes.SBOX[0x01] == 0x7C
    assert aes.SBOX[0x53] == 0xED     # exemplo da secao 5.1.1
    assert aes.SBOX[0xFF] == 0x16
    assert aes.SBOX[0x10] == 0xCA


def teste_sbox_e_bijecao_e_inversa_confere():
    assert sorted(aes.SBOX) == list(range(256))
    for b in range(256):
        assert aes.SBOX_INV[aes.SBOX[b]] == b
        assert aes.SBOX[aes.SBOX_INV[b]] == b
    assert aes.SBOX_INV[0x63] == 0x00


def teste_sbox_sem_pontos_fixos():
    # Propriedade de projeto do AES: S(b) != b e S(b) != ~b para todo b.
    for b in range(256):
        assert aes.SBOX[b] != b
        assert aes.SBOX[b] != b ^ 0xFF


def teste_rcon_dobra_em_gf():
    assert aes.RCON[1:] == [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ============================================================
# EXPANSAO DE CHAVE (w[0]..w[43])
# ============================================================

def teste_expansao_chave_fips_a1_palavras_chave():
    w = aes._expandir_chave(CHAVE_A1)
    assert len(w) == 44 and all(len(p) == 4 for p in w)
    # Valores do Apendice A.1 (w4, w5, w6, w7, w8, w40..w43).
    esperado = {
        4: "a0fafe17", 5: "88542cb1", 6: "23a33939", 7: "2a6c7605",
        8: "f2c295f2", 9: "7a96b943", 10: "5935807a", 11: "7359f67f",
        40: "d014f9a8", 41: "c9ee2589", 42: "e13f0cc8", 43: "b6630ca6",
    }
    for indice, hexa in esperado.items():
        assert _palavra_hex(w[indice]) == hexa, f"w[{indice}]={_palavra_hex(w[indice])}"


def teste_expansao_chave_fips_a1_passos_intermediarios_w4():
    # Apendice A.1, i = 4: temp = w3 = 09cf4f3c
    #   RotWord -> cf4f3c09 ; SubWord -> 8a84eb01 ; Rcon[1] = 01000000
    #   XOR Rcon -> 8b84eb01 ; w4 = w0 XOR isso = a0fafe17
    w3 = [0x09, 0xCF, 0x4F, 0x3C]
    rodada = aes._rot_word(w3)
    assert _palavra_hex(rodada) == "cf4f3c09"
    substituida = aes._sub_word(rodada)
    assert _palavra_hex(substituida) == "8a84eb01"
    substituida[0] ^= aes.RCON[1]
    assert _palavra_hex(substituida) == "8b84eb01"


def teste_expansao_chave_primeiras_palavras_sao_a_propria_chave():
    w = aes._expandir_chave(CHAVE_C1)
    assert b"".join(bytes(p) for p in w[:4]) == CHAVE_C1


def teste_chave_da_rodada_monta_matriz_por_coluna():
    w = aes._expandir_chave(CHAVE_A1)
    k1 = aes._chave_da_rodada(w, 1)
    assert aes._estado_para_bytes(k1).hex() == "a0fafe17" "88542cb1" "23a33939" "2a6c7605"


def teste_expansao_chave_exige_16_bytes():
    for tamanho in (0, 15, 17, 32):
        try:
            aes._expandir_chave(bytes(tamanho))
        except ValueError:
            continue
        raise AssertionError(f"chave de {tamanho} bytes deveria ser rejeitada")


# ============================================================
# OPERACOES DA RODADA (ESTADO 4x4)
# ============================================================

def teste_estado_e_por_coluna():
    bloco = bytes(range(16))
    estado = aes._bytes_para_estado(bloco)
    # estado[linha][coluna] = bloco[linha + 4*coluna]
    assert estado[0] == [0, 4, 8, 12]
    assert estado[1] == [1, 5, 9, 13]
    assert estado[3] == [3, 7, 11, 15]
    assert aes._estado_para_bytes(estado) == bloco


def teste_shift_rows_e_inversa():
    estado = aes._bytes_para_estado(bytes(range(16)))
    deslocado = aes._shift_rows(estado)
    # Linha l rotaciona l posicoes a ESQUERDA.
    assert deslocado[0] == [0, 4, 8, 12]
    assert deslocado[1] == [5, 9, 13, 1]
    assert deslocado[2] == [10, 14, 2, 6]
    assert deslocado[3] == [15, 3, 7, 11]
    assert aes._inv_shift_rows(deslocado) == estado


def teste_shift_rows_exemplo_fips_b():
    entrada = bytes.fromhex("d42711aee0bf98f1b8b45de51e415230")
    esperado = bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5")
    assert aes._estado_para_bytes(aes._shift_rows(aes._bytes_para_estado(entrada))) == esperado


def teste_sub_bytes_e_inversa():
    entrada = bytes.fromhex("193de3bea0f4e22b9ac68d2ae9f84808")
    esperado = bytes.fromhex("d42711aee0bf98f1b8b45de51e415230")   # Apendice B
    estado = aes._bytes_para_estado(entrada)
    assert aes._estado_para_bytes(aes._sub_bytes(estado)) == esperado
    assert aes._inv_sub_bytes(aes._sub_bytes(estado)) == estado


def teste_mix_columns_vetores_conhecidos():
    # Colunas de teste classicas do MixColumns (FIPS-197 / Wikipedia).
    casos = [
        ("db135345", "8e4da1bc"),
        ("f20a225c", "9fdc589d"),
        ("01010101", "01010101"),   # coluna constante e' ponto fixo
        ("c6c6c6c6", "c6c6c6c6"),
        ("d4d4d4d5", "d5d5d7d6"),
        ("2d26314c", "4d7ebdf8"),
    ]
    for entrada, esperado in casos:
        saida = aes._multiplicar_coluna(aes.MATRIZ_MIX, list(bytes.fromhex(entrada)))
        assert bytes(saida).hex() == esperado, f"{entrada} -> {bytes(saida).hex()}"


def teste_mix_columns_exemplo_fips_b_estado_inteiro():
    entrada = bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5")
    esperado = bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")
    estado = aes._bytes_para_estado(entrada)
    assert aes._estado_para_bytes(aes._mix_columns(estado)) == esperado


def teste_inv_mix_columns_desfaz_mix_columns():
    rng = random.Random(7)
    for _ in range(100):
        bloco = bytes(rng.randrange(256) for _ in range(16))
        estado = aes._bytes_para_estado(bloco)
        assert aes._inv_mix_columns(aes._mix_columns(estado)) == estado
        assert aes._mix_columns(aes._inv_mix_columns(estado)) == estado


def teste_matrizes_mix_sao_inversas_entre_si():
    # Produto das duas matrizes em GF(2^8) deve ser a identidade.
    for i in range(4):
        for j in range(4):
            soma = 0
            for k in range(4):
                soma ^= aes._mult_gf(aes.MATRIZ_MIX[i][k], aes.MATRIZ_MIX_INV[k][j])
            assert soma == (1 if i == j else 0), (i, j)


def teste_add_round_key_e_propria_inversa():
    estado = aes._bytes_para_estado(CLARO_C1)
    chave = aes._chave_da_rodada(aes._expandir_chave(CHAVE_C1), 3)
    assert aes._add_round_key(aes._add_round_key(estado, chave), chave) == estado
    assert aes._add_round_key(estado, [[0] * 4] * 4) == estado


# ============================================================
# BLOCO COMPLETO: VETORES OFICIAIS DO FIPS-197
# ============================================================

def teste_bloco_fips_c1():
    w = aes._expandir_chave(CHAVE_C1)
    assert aes._cifrar_bloco(CLARO_C1, w) == CIFRADO_C1
    assert aes._decifrar_bloco(CIFRADO_C1, w) == CLARO_C1


def teste_bloco_fips_apendice_b():
    w = aes._expandir_chave(CHAVE_A1)
    assert aes._cifrar_bloco(CLARO_B, w) == CIFRADO_B
    assert aes._decifrar_bloco(CIFRADO_B, w) == CLARO_B


def teste_rastro_rodadas_do_fips_apendice_b():
    # Estado depois de cada etapa -- Apendice B do FIPS-197.
    rastro = []
    aes._cifrar_bloco(CLARO_B, aes._expandir_chave(CHAVE_A1), rastro)
    etapas = dict(rastro)
    assert etapas["entrada"] == "3243f6a8885a308d313198a2e0370734"
    assert etapas["r0.add_round_key"] == "193de3bea0f4e22b9ac68d2ae9f84808"
    assert etapas["r1.sub_bytes"] == "d42711aee0bf98f1b8b45de51e415230"
    assert etapas["r1.shift_rows"] == "d4bf5d30e0b452aeb84111f11e2798e5"
    assert etapas["r1.mix_columns"] == "046681e5e0cb199a48f8d37a2806264c"
    assert etapas["r1.add_round_key"] == "a49c7ff2689f352b6b5bea43026a5049"
    assert etapas["r10.add_round_key"] == "3925841d02dc09fbdc118597196a0b32"


def teste_erro_rodada_final_nao_tem_mix_columns():
    # Erro classico n.1: aplicar MixColumns tambem na rodada 10.
    rastro = []
    aes._cifrar_bloco(CLARO_B, aes._expandir_chave(CHAVE_A1), rastro)
    nomes = [nome for nome, _ in rastro]
    assert "r9.mix_columns" in nomes
    assert "r10.mix_columns" not in nomes
    assert sum(1 for n in nomes if n.endswith(".mix_columns")) == 9
    assert sum(1 for n in nomes if n.endswith(".add_round_key")) == 11
    assert sum(1 for n in nomes if n.endswith(".sub_bytes")) == 10


def teste_erro_decifracao_final_nao_tem_inv_mix_columns():
    rastro = []
    aes._decifrar_bloco(CIFRADO_B, aes._expandir_chave(CHAVE_A1), rastro)
    nomes = [nome for nome, _ in rastro]
    assert sum(1 for n in nomes if n.endswith(".inv_mix_columns")) == 9
    assert "r0.inv_mix_columns" not in nomes
    # A decifracao comeca pela ULTIMA chave (r10) e termina na primeira (r0).
    assert nomes[1] == "r10.add_round_key"
    assert nomes[-1] == "r0.add_round_key"
    assert dict(rastro)["r0.add_round_key"] == CLARO_B.hex()


def teste_decifracao_espelha_a_cifracao_etapa_a_etapa():
    # O estado antes de cada rodada da decifracao coincide com o estado
    # depois da rodada correspondente da cifracao (lido de tras para frente).
    w = aes._expandir_chave(CHAVE_A1)
    cif, dec = [], []
    aes._cifrar_bloco(CLARO_B, w, cif)
    aes._decifrar_bloco(CIFRADO_B, w, dec)
    c, d = dict(cif), dict(dec)
    assert d["r10.add_round_key"] == c["r10.shift_rows"]
    assert d["r9.inv_shift_rows"] == c["r10.sub_bytes"]
    assert d["r9.inv_sub_bytes"] == c["r9.add_round_key"]
    assert d["r9.add_round_key"] == c["r9.mix_columns"]
    assert d["r9.inv_mix_columns"] == c["r9.shift_rows"]
    assert d["r0.inv_shift_rows"] == c["r1.sub_bytes"]
    assert d["r0.inv_sub_bytes"] == c["r0.add_round_key"]


def teste_bloco_todo_zero_e_todo_ff():
    # Casos de borda: bloco/chave degenerados nao podem quebrar nem vazar padrao.
    w = aes._expandir_chave(bytes(16))
    zero = aes._cifrar_bloco(bytes(16), w)
    assert zero.hex() == "66e94bd4ef8a2c3b884cfa59ca342b2e"   # AES-128(0^128, 0^128)
    assert aes._decifrar_bloco(zero, w) == bytes(16)
    w_ff = aes._expandir_chave(b"\xff" * 16)
    cifrado = aes._cifrar_bloco(b"\xff" * 16, w_ff)
    assert aes._decifrar_bloco(cifrado, w_ff) == b"\xff" * 16


def teste_ida_e_volta_aleatoria_de_blocos():
    rng = random.Random(2024)
    for _ in range(50):
        chave = bytes(rng.randrange(256) for _ in range(16))
        bloco = bytes(rng.randrange(256) for _ in range(16))
        w = aes._expandir_chave(chave)
        assert aes._decifrar_bloco(aes._cifrar_bloco(bloco, w), w) == bloco


def teste_referencia_externa_se_disponivel():
    # Compara com uma implementacao de terceiros (SO nos testes -- o codigo
    # de cifras/aes.py nao usa nenhuma). Sem a biblioteca, o teste e' pulado
    # (os vetores do FIPS acima ja cobrem a corretude).
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return
    rng = random.Random(99)
    for _ in range(100):
        chave = bytes(rng.randrange(256) for _ in range(16))
        bloco = bytes(rng.randrange(256) for _ in range(16))
        referencia = Cipher(algorithms.AES(chave), modes.ECB()).encryptor()
        esperado = referencia.update(bloco) + referencia.finalize()
        assert aes._cifrar_bloco(bloco, aes._expandir_chave(chave)) == esperado


def teste_efeito_avalanche():
    # Trocar 1 bit do texto OU da chave deve mudar ~metade dos 128 bits.
    w = aes._expandir_chave(CHAVE_C1)
    base = aes._cifrar_bloco(CLARO_C1, w)

    def bits_diferentes(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    claro_alterado = bytes([CLARO_C1[0] ^ 0x01]) + CLARO_C1[1:]
    d1 = bits_diferentes(base, aes._cifrar_bloco(claro_alterado, w))
    chave_alterada = bytes([CHAVE_C1[15] ^ 0x80]) + b""
    chave_alterada = CHAVE_C1[:15] + chave_alterada
    d2 = bits_diferentes(base, aes._cifrar_bloco(CLARO_C1, aes._expandir_chave(chave_alterada)))
    assert 40 <= d1 <= 88, d1
    assert 40 <= d2 <= 88, d2


# ============================================================
# CONTRATO DO CHAT (ASCII, chave, Base64)
# ============================================================

CHAVE_EXEMPLO = "Senha1234567890!"  # 16 caracteres ASCII -- cabe exato em 128 bits
CHAVE_HEX = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
REGEX_BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def teste_validar_chave_aceita_ate_16_caracteres():
    assert aes.validar_chave(CHAVE_EXEMPLO) == (True, "")
    assert aes.validar_chave("a") == (True, "")


def teste_validar_chave_rejeita_vazia():
    valida, erro = aes.validar_chave("")
    assert not valida and "vazia" in erro


def teste_validar_chave_rejeita_acima_de_16():
    valida, erro = aes.validar_chave("a" * 17)
    assert not valida and "16" in erro


def teste_validar_chave_rejeita_nao_ascii():
    valida, erro = aes.validar_chave("chave€")
    assert not valida and "ASCII" in erro


def teste_validar_chave_normaliza_acento():
    assert aes.validar_chave("açaí") == (True, "")


def teste_validar_chave_aceita_hexadecimal_do_fips():
    assert aes.validar_chave(CHAVE_HEX) == (True, "")
    assert aes.validar_chave(CHAVE_HEX.replace(" ", "")) == (True, "")
    assert aes.validar_chave(CHAVE_HEX.upper()) == (True, "")


def teste_validar_chave_rejeita_hexadecimal_incompleto_ou_invalido():
    # 30 digitos hex (faltam 2): nao e' hex valido, e como senha passa de 16.
    assert not aes.validar_chave("2b7e151628aed2a6abf7158809cf4f")[0]
    # 32 caracteres com um 'g': nao e' hex e e' longo demais para senha.
    assert not aes.validar_chave("2b7e151628aed2a6abf7158809cf4fgg")[0]


def teste_preparar_chave_completa_com_zeros():
    assert aes._preparar_chave("ab") == b"ab" + b"\x00" * 14
    assert len(aes._preparar_chave(CHAVE_EXEMPLO)) == 16


def teste_preparar_chave_hexadecimal_vira_bytes_crus():
    assert aes._preparar_chave(CHAVE_HEX) == CHAVE_A1
    # Bytes acima de 0x7F so cabem via hexadecimal -- e funcionam.
    alta = aes._preparar_chave("ff" * 16)
    assert alta == b"\xff" * 16


def teste_cifrar_com_chave_hexadecimal_bate_com_fips():
    # 'Cifrar' do chat com o texto de 16 bytes do FIPS-197 C.1 nao e'
    # ASCII puro (tem bytes de controle); usa 0x32..0x37 'texto' em ASCII e
    # confere contra o motor, que ja bate com o FIPS.
    texto = "0123456789ABCDEF"
    cifrado = aes.cifrar(texto, CHAVE_HEX)
    esperado = aes._cifrar_bloco(texto.encode("ascii"), aes._expandir_chave(CHAVE_A1))
    assert aes.bytes_brutos(cifrado)[:16] == esperado
    assert aes.decifrar(cifrado, CHAVE_HEX) == texto


def teste_cifrar_produz_base64_valido():
    cifrado = aes.cifrar("Atacar base norte.", CHAVE_EXEMPLO)
    assert REGEX_BASE64.match(cifrado), cifrado
    assert all(ord(c) < 128 for c in cifrado)
    # 18 bytes -> 2 blocos de 16 = 32 bytes -> 44 caracteres Base64.
    assert len(base64.b64decode(cifrado)) == 32


def teste_ida_e_volta_round_trip():
    for texto in ["Ola mundo!", "Atacar base norte.", "a", "x" * 15, "x" * 16, "x" * 17,
                  "x" * 100, "Texto, com: pontuacao? 123 {ok} ~"]:
        assert aes.decifrar(aes.cifrar(texto, CHAVE_EXEMPLO), CHAVE_EXEMPLO) == texto, texto


def teste_ida_e_volta_com_chave_curta():
    assert aes.decifrar(aes.cifrar("mensagem", "k"), "k") == "mensagem"


def teste_ida_e_volta_todos_os_ascii_imprimiveis():
    texto = "".join(chr(c) for c in range(32, 127))
    assert aes.decifrar(aes.cifrar(texto, CHAVE_EXEMPLO), CHAVE_EXEMPLO) == texto


def teste_texto_vazio_produz_criptograma_vazio():
    assert aes.cifrar("", CHAVE_EXEMPLO) == ""
    assert aes.decifrar("", CHAVE_EXEMPLO) == ""


def teste_tamanho_do_criptograma_e_multiplo_de_16_bytes():
    # Erro classico: esquecer o padding do ultimo bloco parcial.
    for n in (1, 15, 16, 17, 31, 32, 33):
        bruto = aes.bytes_brutos(aes.cifrar("a" * n, CHAVE_EXEMPLO))
        assert len(bruto) == 16 * ((n + 15) // 16), (n, len(bruto))


def teste_ecb_blocos_iguais_geram_criptogramas_iguais():
    # Propriedade (e fraqueza didatica) do ECB, para documentar o modo usado.
    bruto = aes.bytes_brutos(aes.cifrar("A" * 32, CHAVE_EXEMPLO))
    assert bruto[:16] == bruto[16:32]


def teste_mesma_mensagem_chaves_diferentes_criptogramas_diferentes():
    assert aes.cifrar("Ola", "chaveA") != aes.cifrar("Ola", "chaveB")


def teste_chave_errada_nao_recupera_o_texto():
    cifrado = aes.cifrar("Atacar base norte.", CHAVE_EXEMPLO)
    assert aes.decifrar(cifrado, "OutraChave") != "Atacar base norte."


def teste_decifrar_com_chave_errada_nao_derruba_o_cliente():
    cifrado = aes.cifrar("Atacar base norte.", CHAVE_EXEMPLO)
    resultado = aes.decifrar(cifrado, "OutraChave")
    assert isinstance(resultado, str) and all(ord(c) < 128 for c in resultado)


def teste_decifrar_lixo_nao_derruba_o_cliente():
    for lixo in ["", "!!!!", "abc", "não é base64 €", "A" * 7, "AAAA" * 3, "====", "\x00\x01"]:
        assert isinstance(aes.decifrar(lixo, CHAVE_EXEMPLO), str)


def teste_bytes_brutos_bate_com_cifrar():
    cifrado = aes.cifrar("Ola", CHAVE_EXEMPLO)
    assert aes.bytes_brutos(cifrado) == base64.b64decode(cifrado)
    assert len(aes.bytes_brutos(cifrado)) == 16
    assert aes.bytes_brutos("") == b""


def teste_cifrar_com_chave_invalida_estoura_valueerror_claro():
    for chave in ["", "a" * 17, "€"]:
        try:
            aes.cifrar("Ola", chave)
        except ValueError:
            continue
        raise AssertionError(f"chave {chave!r} deveria levantar ValueError")


def teste_registro_expoe_aes_na_opcao_8():
    from cifras.registro import CIFRAS, NOMES
    assert CIFRAS["8"] is aes
    assert "AES" in NOMES["8"]
    for funcao in ("validar_chave", "cifrar", "decifrar"):
        assert callable(getattr(aes, funcao))


TESTES = [
    teste_xtime_exemplos_do_fips,
    teste_xtime_so_estoura_com_bit_7,
    teste_mult_gf_exemplos_do_fips,
    teste_mult_gf_propriedades,
    teste_inverso_gf,
    teste_sbox_valores_conhecidos,
    teste_sbox_e_bijecao_e_inversa_confere,
    teste_sbox_sem_pontos_fixos,
    teste_rcon_dobra_em_gf,
    teste_expansao_chave_fips_a1_palavras_chave,
    teste_expansao_chave_fips_a1_passos_intermediarios_w4,
    teste_expansao_chave_primeiras_palavras_sao_a_propria_chave,
    teste_chave_da_rodada_monta_matriz_por_coluna,
    teste_expansao_chave_exige_16_bytes,
    teste_estado_e_por_coluna,
    teste_shift_rows_e_inversa,
    teste_shift_rows_exemplo_fips_b,
    teste_sub_bytes_e_inversa,
    teste_mix_columns_vetores_conhecidos,
    teste_mix_columns_exemplo_fips_b_estado_inteiro,
    teste_inv_mix_columns_desfaz_mix_columns,
    teste_matrizes_mix_sao_inversas_entre_si,
    teste_add_round_key_e_propria_inversa,
    teste_bloco_fips_c1,
    teste_bloco_fips_apendice_b,
    teste_rastro_rodadas_do_fips_apendice_b,
    teste_erro_rodada_final_nao_tem_mix_columns,
    teste_erro_decifracao_final_nao_tem_inv_mix_columns,
    teste_decifracao_espelha_a_cifracao_etapa_a_etapa,
    teste_bloco_todo_zero_e_todo_ff,
    teste_ida_e_volta_aleatoria_de_blocos,
    teste_referencia_externa_se_disponivel,
    teste_efeito_avalanche,
    teste_validar_chave_aceita_ate_16_caracteres,
    teste_validar_chave_rejeita_vazia,
    teste_validar_chave_rejeita_acima_de_16,
    teste_validar_chave_rejeita_nao_ascii,
    teste_validar_chave_normaliza_acento,
    teste_validar_chave_aceita_hexadecimal_do_fips,
    teste_validar_chave_rejeita_hexadecimal_incompleto_ou_invalido,
    teste_preparar_chave_completa_com_zeros,
    teste_preparar_chave_hexadecimal_vira_bytes_crus,
    teste_cifrar_com_chave_hexadecimal_bate_com_fips,
    teste_cifrar_produz_base64_valido,
    teste_ida_e_volta_round_trip,
    teste_ida_e_volta_com_chave_curta,
    teste_ida_e_volta_todos_os_ascii_imprimiveis,
    teste_texto_vazio_produz_criptograma_vazio,
    teste_tamanho_do_criptograma_e_multiplo_de_16_bytes,
    teste_ecb_blocos_iguais_geram_criptogramas_iguais,
    teste_mesma_mensagem_chaves_diferentes_criptogramas_diferentes,
    teste_chave_errada_nao_recupera_o_texto,
    teste_decifrar_com_chave_errada_nao_derruba_o_cliente,
    teste_decifrar_lixo_nao_derruba_o_cliente,
    teste_bytes_brutos_bate_com_cifrar,
    teste_cifrar_com_chave_invalida_estoura_valueerror_claro,
    teste_registro_expoe_aes_na_opcao_8,
]


def rodar_todos():
    falhas = 0
    for teste in TESTES:
        try:
            teste()
            print(f"[OK]    {teste.__name__}")
        except AssertionError as e:
            falhas += 1
            print(f"[FALHA] {teste.__name__} -- {e}")

    print(f"\n{len(TESTES) - falhas}/{len(TESTES)} testes passaram.")
    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
