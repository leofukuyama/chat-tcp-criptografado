"""
Testes isolados da Cifra AES-128 -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_aes.py  (a partir da raiz do projeto)

Os vetores vem de duas fontes:

  1. Os slides da aula ("AULA AES.pdf"), que o codigo segue passo a passo:
     - SubBytes pela tabela S-box (linha = digito da esquerda, coluna = digito
       da direita) e a S-box inversa;
     - multiplicacao por 02 = deslocar 1 bit a esquerda e, se o bit que saiu
       era 1, XOR com 1B; multiplicacao por 03 = (x * 02) XOR x;
     - InvMixColumns com 0E/0B/0D/09 montados a partir dos multiplos 02, 04 e
       08 do byte, escolhidos pelos bits da constante;
     - expansao de chave (RotWord, SubWord, Rcon) com a chave
       0f 15 71 c9 47 d9 e8 59 0c b7 ad d6 af 7f 67 98.
  2. O FIPS-197 (o documento oficial do AES), que confere o algoritmo inteiro:
     - Apendice A.1: expansao da chave 2b7e1516 28aed2a6 abf71588 09cf4f3c
     - Apendice B:   cifragem de 3243f6a8 885a308d 313198a2 e0370734, com o
                     estado depois de cada etapa das rodadas
     - Apendice C.1: chave 000102...0f, texto claro 00112233...ff
Alem deles, ha testes dirigidos aos erros mais comuns ao implementar o
AES (ver teste_erro_* e teste_rastro_*).
"""

import base64
import hashlib
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

# --- Chave usada nos slides de expansao de chave ---------------------------
CHAVE_AULA = bytes.fromhex("0f1571c947d9e8590cb7add6af7f6798")


def _palavra_hex(palavra: list[int]) -> str:
    return bytes(palavra).hex()


# ============================================================
# MULTIPLICACAO DE BYTES (como na aula: deslocar e fazer XOR)
# ============================================================

def teste_multiplicar_por_2_sem_correcao_quando_o_primeiro_bit_e_0():
    # Slide: 02 x 47 -> 0100 0111 desloca para 1000 1110 = 8E (sem XOR com 1B).
    assert aes._multiplicar_por_2(0x47) == 0x8E
    assert aes._multiplicar_por_2(0x7F) == 0xFE


def teste_multiplicar_por_2_com_correcao_1b_quando_o_primeiro_bit_e_1():
    # Slide: 02 x 8E -> 1 0001 1100, descarta o 9o bit (1C), XOR com 1B = 07.
    assert aes._multiplicar_por_2(0x8E) == 0x07
    assert aes._multiplicar_por_2(0x80) == 0x1B
    assert aes._multiplicar_por_2(0xFF) == 0xE5
    # Exercicio de MixColumns do slide: 2*FC = E3 e 2*E4 = D3.
    assert aes._multiplicar_por_2(0xFC) == 0xE3
    assert aes._multiplicar_por_2(0xE4) == 0xD3
    # Primeiro termo de S00 do slide: 2*87 (0E XOR 1B = 15).
    assert aes._multiplicar_por_2(0x87) == 0x15


def teste_multiplicar_por_3_e_o_dobro_xor_o_proprio_byte():
    # Slide: 03 x 6E = (6E << 1) XOR 6E = DC XOR 6E = B2;  03 x E4 = D3 XOR E4 = 37.
    assert aes._multiplicar(0x03, 0x6E) == 0xB2
    assert aes._multiplicar(0x03, 0xE4) == 0x37
    for byte in range(256):
        assert aes._multiplicar(0x03, byte) == aes._multiplicar_por_2(byte) ^ byte


def teste_multiplicar_por_01_e_por_02_sao_o_proprio_byte_e_o_dobro():
    for byte in range(256):
        assert aes._multiplicar(0x01, byte) == byte
        assert aes._multiplicar(0x02, byte) == aes._multiplicar_por_2(byte)


def teste_multiplos_de_47_por_02_04_e_08_da_aula():
    # Slide: cada multiplo reaproveita o anterior (02 x 47 = 8E, 04 x 47 = 07, 08 x 47 = 0E).
    assert aes._multiplicar(0x02, 0x47) == 0x8E
    assert aes._multiplicar(0x04, 0x47) == 0x07
    assert aes._multiplicar(0x08, 0x47) == 0x0E


def teste_multiplicar_pelas_constantes_do_inv_mix_columns_da_aula():
    # Os bits da constante dizem quais multiplos entram no XOR:
    #   0E = 08,04,02   0B = 08,02,01   0D = 08,04,01   09 = 08,01
    # (constante, byte, produto) tirados dos slides, coluna 47 37 94 ED e S01.
    casos = [
        (0x0E, 0x47, 0x87), (0x0B, 0x37, 0xFA), (0x0D, 0x94, 0x3E), (0x09, 0xED, 0xC4),  # S00
        (0x09, 0x47, 0x49), (0x0E, 0x37, 0x11), (0x0B, 0x94, 0x6B), (0x0D, 0xED, 0x5D),  # 2a linha
        (0x0D, 0x47, 0x4E), (0x09, 0x37, 0x94), (0x0E, 0x94, 0x99), (0x0B, 0xED, 0x05),  # 3a linha
        (0x0B, 0x47, 0xC7), (0x0D, 0x37, 0x48), (0x09, 0x94, 0x58), (0x0E, 0xED, 0x71),  # 4a linha
        (0x0E, 0x40, 0xAD), (0x0B, 0xD4, 0x9D), (0x0D, 0xE4, 0x38), (0x09, 0xA5, 0xFA),  # S01
    ]
    for constante, byte, esperado in casos:
        obtido = aes._multiplicar(constante, byte)
        assert obtido == esperado, f"{constante:02X} x {byte:02X} = {obtido:02X}, esperado {esperado:02X}"


def teste_multiplicar_rejeita_constante_com_mais_de_4_bits():
    # So existem as constantes 01..0F nas matrizes do MixColumns/InvMixColumns;
    # acima disso o metodo dos multiplos 01/02/04/08 deixaria bits de fora.
    for constante in (0x10, 0x1B, 0xFF):
        try:
            aes._multiplicar(constante, 0x01)
        except ValueError:
            continue
        raise AssertionError(f"constante {constante:#04x} deveria ser rejeitada")


# ============================================================
# S-BOX (TABELA 16x16) E RCON
# ============================================================

# Linhas da Tabela 5.2 dos slides, copiadas dali: x = linha, y = coluna.
SBOX_LINHA_0 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]
SBOX_LINHA_8 = [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73]
SBOX_LINHA_F = [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
SBOX_INV_LINHA_0 = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]
SBOX_INV_LINHA_F = [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]


def _achatar(tabela: list[list[int]]) -> bytes:
    return bytes(valor for linha in tabela for valor in linha)


def teste_sbox_e_sbox_inversa_sao_tabelas_16_por_16():
    for tabela in (aes.SBOX, aes.SBOX_INV):
        assert len(tabela) == 16
        assert all(len(linha) == 16 for linha in tabela)
        assert all(0 <= valor <= 255 for linha in tabela for valor in linha)


def teste_sbox_busca_a_linha_pela_esquerda_e_a_coluna_pela_direita():
    # Byte 53: linha 5, coluna 3 -> ED (exemplo do FIPS-197, secao 5.1.1).
    assert aes.SBOX[0x5][0x3] == 0xED
    assert aes._substituir_byte(0x53, aes.SBOX) == 0xED
    assert aes._substituir_byte(0x00, aes.SBOX) == 0x63
    assert aes._substituir_byte(0xFF, aes.SBOX) == 0x16
    # 0x10 = linha 1, coluna 0 -> CA (trocar linha por coluna daria 7C).
    assert aes._substituir_byte(0x10, aes.SBOX) == 0xCA
    assert aes._substituir_byte(0x63, aes.SBOX_INV) == 0x00


def teste_sbox_confere_com_as_linhas_dos_slides():
    assert aes.SBOX[0x0] == SBOX_LINHA_0
    assert aes.SBOX[0x8] == SBOX_LINHA_8
    assert aes.SBOX[0xF] == SBOX_LINHA_F
    assert aes.SBOX_INV[0x0] == SBOX_INV_LINHA_0
    assert aes.SBOX_INV[0xF] == SBOX_INV_LINHA_F


def teste_sbox_e_bijecao_e_inversa_confere():
    assert sorted(_achatar(aes.SBOX)) == list(range(256))
    assert sorted(_achatar(aes.SBOX_INV)) == list(range(256))
    for byte in range(256):
        trocado = aes._substituir_byte(byte, aes.SBOX)
        assert aes._substituir_byte(trocado, aes.SBOX_INV) == byte
        trocado = aes._substituir_byte(byte, aes.SBOX_INV)
        assert aes._substituir_byte(trocado, aes.SBOX) == byte


def teste_sbox_tabelas_completas_conferem_com_as_do_fips():
    # Guarda contra erro de digitacao nas 512 entradas: impressao digital
    # (SHA-256) das tabelas oficiais do FIPS-197 (Figuras 7 e 14).
    assert hashlib.sha256(_achatar(aes.SBOX)).hexdigest() == (
        "c2d8e5eed6cbebd8625fc18f81486a7733c04f9b0129ffbe974c68b90308b4f2")
    assert hashlib.sha256(_achatar(aes.SBOX_INV)).hexdigest() == (
        "93631b0726f6fe6629daa743ee51b49f4477ed07391b68eeea0672a4a90018aa")


def teste_rcon_valores_da_aula():
    # Slide da tabela de chaves: Rcon(1) = 01, Rcon(2) = 02, ... Rcon(9) = 1B, Rcon(10) = 36.
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


def teste_rot_word_e_sub_word_exemplos_da_aula():
    # Slides: RotWord(7F 8D 29 2F) = 8D 29 2F 7F; SubWord(8D 29 2F 7F) = 5D A5 15 D2.
    assert aes._rot_word([0x7F, 0x8D, 0x29, 0x2F]) == [0x8D, 0x29, 0x2F, 0x7F]
    assert aes._sub_word([0x8D, 0x29, 0x2F, 0x7F]) == [0x5D, 0xA5, 0x15, 0xD2]
    # Slide do Rcon: 5D A5 15 D2 XOR 1B 00 00 00 = 46 A5 15 D2.
    assert _palavra_hex([0x5D ^ 0x1B, 0xA5, 0x15, 0xD2]) == "46a515d2"


def teste_expansao_chave_da_aula_passo_a_passo():
    # Slides "Chave de rodada": chave 0f 15 71 c9 | 47 d9 e8 59 | 0c b7 ad d6 | af 7f 67 98.
    w = aes._expandir_chave(CHAVE_AULA)
    # i = 4: temp = w3 = af 7f 67 98 -> RotWord 7f 67 98 af -> SubWord d2 85 46 79
    #        -> XOR Rcon(1) = 01 00 00 00 -> d3 85 46 79 -> w4 = w0 XOR temp.
    rodada = aes._rot_word(w[3])
    assert _palavra_hex(rodada) == "7f6798af"
    substituida = aes._sub_word(rodada)
    assert _palavra_hex(substituida) == "d2854679"
    substituida[0] ^= aes.RCON[4 // 4]
    assert _palavra_hex(substituida) == "d3854679"
    assert _palavra_hex(w[4]) == "dc9037b0"
    # i = 5, 6, 7: i mod 4 != 0, so w[i] = w[i-4] XOR w[i-1].
    assert _palavra_hex(w[5]) == "9b49dfe9"
    assert _palavra_hex(w[6]) == "97fe723f"
    assert _palavra_hex(w[7]) == "388115a7"
    # i = 8: temp = w7 = 38 81 15 a7 -> RotWord 81 15 a7 38 -> SubWord 0c 59 5c 07
    #        -> XOR Rcon(2) = 02 00 00 00 -> 0e 59 5c 07 -> w8 = w4 XOR temp.
    rodada = aes._rot_word(w[7])
    assert _palavra_hex(rodada) == "8115a738"
    substituida = aes._sub_word(rodada)
    assert _palavra_hex(substituida) == "0c595c07"
    substituida[0] ^= aes.RCON[8 // 4]
    assert _palavra_hex(substituida) == "0e595c07"
    assert _palavra_hex(w[8]) == "d2c96bb7"


def teste_expansao_chave_da_aula_palavras_finais_da_tabela():
    # Tabela do slide "Seguindo o algoritmo teremos as 44 palavras de 32 bits".
    # (w35 esta com um digito a menos no slide; o RotWord(w35) ao lado mostra be 0b 38 3c.)
    w = aes._expandir_chave(CHAVE_AULA)
    assert len(w) == 44
    esperado = {
        28: "37149348", 29: "bb3de7f7", 30: "38d808a5", 31: "f77da14a",
        32: "48264520", 33: "f31ba2d7", 34: "cbc3aa72", 35: "3cbe0b38",
        36: "fd0d42cb", 37: "0e16e01c", 38: "c5d54a6e", 39: "f96b4156",
        40: "b48ef352", 41: "ba98134e", 42: "7f4d5920", 43: "86261876",
    }
    for indice, hexa in esperado.items():
        assert _palavra_hex(w[indice]) == hexa, f"w[{indice}]={_palavra_hex(w[indice])}"
    # Slide "matriz preenchida por colunas": w0 vira a 1a coluna 0f 15 71 c9.
    k0 = aes._chave_da_rodada(w, 0)
    assert [k0[linha][0] for linha in range(4)] == [0x0F, 0x15, 0x71, 0xC9]
    assert [k0[0][coluna] for coluna in range(4)] == [0x0F, 0x47, 0x0C, 0xAF]
    k1 = aes._chave_da_rodada(w, 1)
    assert [k1[linha][0] for linha in range(4)] == [0xDC, 0x90, 0x37, 0xB0]


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


# Estado dos slides de MixColumns / InvMixColumns, linha por linha:
# a entrada do MixColumns e a entrada do InvMixColumns sao pares exatos.
ESTADO_ANTES_DO_MIX = [
    [0x87, 0xF2, 0x4D, 0x97],
    [0x6E, 0x4C, 0x90, 0xEC],
    [0x46, 0xE7, 0x4A, 0xC3],
    [0xA6, 0x8C, 0xD8, 0x95],
]
ESTADO_DEPOIS_DO_MIX = [
    [0x47, 0x40, 0xA3, 0x4C],
    [0x37, 0xD4, 0x70, 0x9F],
    [0x94, 0xE4, 0x3A, 0x42],
    [0xED, 0xA5, 0xA6, 0xBC],
]


def teste_mix_columns_primeiros_bytes_do_slide():
    # S00 = (2*87) XOR (3*6E) XOR 46 XOR A6 = 15 XOR B2 XOR 46 XOR A6 = 47
    coluna_0 = [0x87, 0x6E, 0x46, 0xA6]
    assert aes._multiplicar_coluna(aes.MATRIZ_MIX, coluna_0)[0] == 0x47
    assert (aes._multiplicar(0x02, 0x87) ^ aes._multiplicar(0x03, 0x6E) ^ 0x46 ^ 0xA6) == 0x47
    # S01 = (2*F2) XOR (3*4C) XOR E7 XOR 8C = 40
    coluna_1 = [0xF2, 0x4C, 0xE7, 0x8C]
    assert aes._multiplicar_coluna(aes.MATRIZ_MIX, coluna_1)[0] == 0x40


def teste_mix_columns_exercicio_do_slide_coluna_8b_7f_fc_e4():
    # Exercicio: 3a linha da matriz (01 01 02 03) sobre a coluna 8b 7f fc e4:
    # 8b XOR 7f XOR (2*fc) XOR (3*e4) = 8b XOR 7f XOR e3 XOR 37 = 20.
    coluna = [0x8B, 0x7F, 0xFC, 0xE4]
    assert aes._multiplicar_coluna(aes.MATRIZ_MIX, coluna)[2] == 0x20


def teste_mix_columns_estado_inteiro_do_slide():
    assert aes._mix_columns(ESTADO_ANTES_DO_MIX) == ESTADO_DEPOIS_DO_MIX


def teste_inv_mix_columns_estado_inteiro_do_slide():
    # "A matriz original recuperada": 47 40 A3 4C / ... -> 87 F2 4D 97 / ...
    assert aes._inv_mix_columns(ESTADO_DEPOIS_DO_MIX) == ESTADO_ANTES_DO_MIX


def teste_inv_mix_columns_primeira_coluna_do_slide():
    # Coluna 47 37 94 ED -> 87 6E 46 A6 (S00 = 87, depois 6E, 46 e A6).
    coluna = [0x47, 0x37, 0x94, 0xED]
    assert aes._multiplicar_coluna(aes.MATRIZ_MIX_INV, coluna) == [0x87, 0x6E, 0x46, 0xA6]
    assert (aes._multiplicar(0x0E, 0x47) ^ aes._multiplicar(0x0B, 0x37)
            ^ aes._multiplicar(0x0D, 0x94) ^ aes._multiplicar(0x09, 0xED)) == 0x87


def teste_inv_mix_columns_desfaz_mix_columns():
    rng = random.Random(7)
    for _ in range(100):
        bloco = bytes(rng.randrange(256) for _ in range(16))
        estado = aes._bytes_para_estado(bloco)
        assert aes._inv_mix_columns(aes._mix_columns(estado)) == estado
        assert aes._mix_columns(aes._inv_mix_columns(estado)) == estado


def teste_matrizes_mix_sao_inversas_entre_si():
    # Produto das duas matrizes (multiplicando como na aula e somando com
    # XOR) deve ser a identidade.
    for i in range(4):
        for j in range(4):
            soma = 0
            for k in range(4):
                soma ^= aes._multiplicar(aes.MATRIZ_MIX[i][k], aes.MATRIZ_MIX_INV[k][j])
            assert soma == (1 if i == j else 0), (i, j)


def teste_add_round_key_exemplo_do_slide():
    # Slide: 47 XOR AC = EB (0100 0111 XOR 1010 1100 = 1110 1011).
    estado = [[0x47, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    chave = [[0xAC, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    assert aes._add_round_key(estado, chave)[0][0] == 0xEB


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
    teste_multiplicar_por_2_sem_correcao_quando_o_primeiro_bit_e_0,
    teste_multiplicar_por_2_com_correcao_1b_quando_o_primeiro_bit_e_1,
    teste_multiplicar_por_3_e_o_dobro_xor_o_proprio_byte,
    teste_multiplicar_por_01_e_por_02_sao_o_proprio_byte_e_o_dobro,
    teste_multiplos_de_47_por_02_04_e_08_da_aula,
    teste_multiplicar_pelas_constantes_do_inv_mix_columns_da_aula,
    teste_multiplicar_rejeita_constante_com_mais_de_4_bits,
    teste_sbox_e_sbox_inversa_sao_tabelas_16_por_16,
    teste_sbox_busca_a_linha_pela_esquerda_e_a_coluna_pela_direita,
    teste_sbox_confere_com_as_linhas_dos_slides,
    teste_sbox_e_bijecao_e_inversa_confere,
    teste_sbox_tabelas_completas_conferem_com_as_do_fips,
    teste_rcon_valores_da_aula,
    teste_expansao_chave_fips_a1_palavras_chave,
    teste_expansao_chave_fips_a1_passos_intermediarios_w4,
    teste_rot_word_e_sub_word_exemplos_da_aula,
    teste_expansao_chave_da_aula_passo_a_passo,
    teste_expansao_chave_da_aula_palavras_finais_da_tabela,
    teste_expansao_chave_primeiras_palavras_sao_a_propria_chave,
    teste_chave_da_rodada_monta_matriz_por_coluna,
    teste_expansao_chave_exige_16_bytes,
    teste_estado_e_por_coluna,
    teste_shift_rows_e_inversa,
    teste_shift_rows_exemplo_fips_b,
    teste_sub_bytes_e_inversa,
    teste_mix_columns_vetores_conhecidos,
    teste_mix_columns_exemplo_fips_b_estado_inteiro,
    teste_mix_columns_primeiros_bytes_do_slide,
    teste_mix_columns_exercicio_do_slide_coluna_8b_7f_fc_e4,
    teste_mix_columns_estado_inteiro_do_slide,
    teste_inv_mix_columns_estado_inteiro_do_slide,
    teste_inv_mix_columns_primeira_coluna_do_slide,
    teste_inv_mix_columns_desfaz_mix_columns,
    teste_matrizes_mix_sao_inversas_entre_si,
    teste_add_round_key_exemplo_do_slide,
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
