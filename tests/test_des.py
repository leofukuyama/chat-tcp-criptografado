"""
Testes isolados da Cifra DES -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_des.py  (a partir da raiz do projeto)
"""

import base64
import os
import re
import sys

# Garante que o pacote cifras/ seja encontrado mesmo rodando este arquivo
# diretamente de dentro da pasta tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import des


def _bits(texto: str) -> list[int]:
    """Converte uma string de bits com espaços/quebras de linha (formato dos
    slides da disciplina, ex.: "0110 1111") numa lista de 0/1, ignorando
    qualquer caractere que não seja '0' ou '1'."""
    return [int(c) for c in texto if c in "01"]


def teste_bytes_para_bits_e_volta():
    dados = bytes([0b10110001, 0b00000001])
    bits = des._bytes_para_bits(dados)
    assert bits == [1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], (
        f"bits obtidos: {bits}"
    )
    assert des._bits_para_bytes(bits) == dados


def teste_permutar_tabela_simples():
    # Tabela 1-indexada: posição i do resultado = bits[tabela[i] - 1].
    bits = [1, 0, 1, 1]
    tabela = [4, 1, 3, 2]
    assert des._permutar(bits, tabela) == [1, 1, 1, 0]


def teste_deslocar_esquerda():
    bits = [1, 1, 0, 0, 0, 1, 0, 1]
    assert des._deslocar_esquerda(bits, 1) == [1, 0, 0, 0, 1, 0, 1, 1]
    assert des._deslocar_esquerda(bits, 2) == [0, 0, 0, 1, 0, 1, 1, 1]


def teste_xor():
    assert des._xor([1, 0, 1, 1], [0, 0, 1, 1]) == [1, 0, 0, 0]


def teste_ip_exemplo_pdf():
    # Slide "DES-APLICACAO": bloco = "Atacar b" (primeiros 8 bytes de
    # "Atacar base norte."), depois de passar pela permutacao inicial IP.
    bloco = bytes.fromhex("4174616361722062")
    bits = des._bytes_para_bits(bloco)
    permutado = des._permutar(bits, des.IP)
    esperado = _bits(
        "1011 1111 0010 0010 0000 0010 0001 1101 "
        "0000 0000 1111 1110 0000 0000 1010 1000"
    )
    assert permutado == esperado


def teste_subchaves_vetor_classico_livro_texto():
    # M=0123456789ABCDEF, K=133457799BBCDFF1 -> C=85E813540F0AB405 e' o
    # vetor de teste classico do DES (Stallings/Forouzan), tambem usado
    # nos slides da disciplina para ilustrar a geracao de subchaves (K1
    # e K2 aparecem explicitamente no PDF a partir dessa mesma chave).
    chave = bytes.fromhex("133457799BBCDFF1")
    subchaves = des._gerar_subchaves(chave)
    assert len(subchaves) == 16
    assert all(len(k) == 48 for k in subchaves)
    assert subchaves[0] == _bits(
        "000110 110000 001011 101111 111111 000111 000001 110010"
    )
    assert subchaves[1] == _bits(
        "011110 011010 111011 011001 110110 111100 100111 100101"
    )


def teste_subchaves_exemplo_atacar_base_norte():
    # Chave usada no exemplo pratico do PDF ("Atacar base norte.").
    chave = bytes.fromhex("0123456789ABCDEF")
    subchaves = des._gerar_subchaves(chave)
    assert subchaves[0] == _bits(
        "000010 110000 001001 100111 100110 110100 100110 100101"
    )
    assert subchaves[1] == _bits(
        "011010 011010 011001 011001 001001 010110 101000 100110"
    )
    assert subchaves[2] == _bits(
        "010001 011101 010010 001010 101101 000010 100011 010010"
    )


def teste_expansao_e_sbox_exemplo_pdf():
    # Rodada 1 do primeiro bloco de "Atacar base norte." (README-DES.md
    # secao 7.4) -- valida E, XOR com a subchave, saida das 8 S-BOX e a
    # permutacao P, um passo de cada vez.
    r0 = _bits("0000 0000 1111 1110 0000 0000 1010 1000")
    k1 = _bits("000010 110000 001001 100111 100110 110100 100110 100101")

    expandido = des._expandir(r0)
    assert expandido == _bits(
        "000000 000001 011111 111100 000000 000001 010101 010000"
    )

    xor_resultado = des._xor(expandido, k1)
    assert xor_resultado == _bits(
        "000010 110001 010110 011011 100110 110101 110011 110101"
    )

    sbox_saida = des._substituir_sbox(xor_resultado)
    assert sbox_saida == _bits("0100 1011 0111 1010 1011 0001 0101 1001")

    f = des._funcao_f(r0, k1)
    assert f == _bits("0110 1111 0101 1001 1110 1000 1100 0100")


def teste_rodadas_1_a_3_exemplo_pdf():
    # Reproduz manualmente as 3 primeiras rodadas de Feistel do primeiro
    # bloco de "Atacar base norte." e compara L/R contra os slides.
    chave = bytes.fromhex("0123456789ABCDEF")
    subchaves = des._gerar_subchaves(chave)

    l0 = _bits("1011 1111 0010 0010 0000 0010 0001 1101")
    r0 = _bits("0000 0000 1111 1110 0000 0000 1010 1000")

    f1 = des._funcao_f(r0, subchaves[0])
    l1 = r0
    r1 = des._xor(l0, f1)
    assert r1 == _bits("1101 0000 0111 1011 1110 1010 1101 1001")

    f2 = des._funcao_f(r1, subchaves[1])
    l2 = r1
    r2 = des._xor(l1, f2)
    assert r2 == _bits("1101 0111 1100 1001 1111 0000 1100 0100")

    f3 = des._funcao_f(r2, subchaves[2])
    r3 = des._xor(l2, f3)
    assert r3 == _bits("0101 1100 0101 0001 1100 1101 1111 1001")


def teste_bloco_vetor_classico_livro_texto():
    bloco = bytes.fromhex("0123456789ABCDEF")
    chave = bytes.fromhex("133457799BBCDFF1")
    subchaves = des._gerar_subchaves(chave)

    cifrado = des._cifrar_bloco(bloco, subchaves)
    assert cifrado.hex().upper() == "85E813540F0AB405", cifrado.hex()

    decifrado = des._decifrar_bloco(cifrado, subchaves)
    assert decifrado == bloco


def teste_bloco_exemplo_atacar_base_norte():
    # Primeiro bloco de "Atacar base norte." ("Atacar b") com a chave do
    # PDF -- confirma que as 16 rodadas completas (nao so as 3 primeiras
    # do teste_rodadas_1_a_3_exemplo_pdf) fecham no resultado certo.
    bloco = bytes.fromhex("4174616361722062")
    chave = bytes.fromhex("0123456789ABCDEF")
    subchaves = des._gerar_subchaves(chave)

    cifrado = des._cifrar_bloco(bloco, subchaves)
    assert cifrado.hex().upper() == "3044351B5A18C03D", cifrado.hex()

    decifrado = des._decifrar_bloco(cifrado, subchaves)
    assert decifrado == bloco


def teste_mensagem_completa_exemplo_pdf():
    # Os 3 blocos de 8 bytes de "Atacar base norte." (ultimo com padding
    # de zeros) contra o criptograma completo dado no PDF.
    chave = bytes.fromhex("0123456789ABCDEF")
    subchaves = des._gerar_subchaves(chave)

    texto_com_padding = b"Atacar base norte." + b"\x00" * 6
    assert len(texto_com_padding) == 24
    blocos_claros = [
        texto_com_padding[i:i + 8] for i in range(0, 24, 8)
    ]
    assert blocos_claros[0] == b"Atacar b"
    assert blocos_claros[1] == b"ase nort"
    assert blocos_claros[2] == b"e.\x00\x00\x00\x00\x00\x00"

    cifrado = b"".join(des._cifrar_bloco(b, subchaves) for b in blocos_claros)
    assert cifrado.hex().upper() == (
        "3044351B5A18C03DEF5FE56B50211EF3DF4EE0859A96E988"
    ), cifrado.hex()

    decifrado = b"".join(
        des._decifrar_bloco(cifrado[i:i + 8], subchaves) for i in range(0, 24, 8)
    )
    assert decifrado == texto_com_padding


CHAVE_EXEMPLO = "Senha123"  # 8 caracteres ASCII -- cabe exato em 64 bits
REGEX_BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def teste_validar_chave_aceita_ate_8_caracteres():
    valido, erro = des.validar_chave("Senha123")
    assert valido is True, f"Chave de 8 caracteres foi rejeitada: {erro}"


def teste_validar_chave_aceita_curta():
    valido, erro = des.validar_chave("ab")
    assert valido is True, f"Chave curta deveria ser aceita (padding): {erro}"


def teste_validar_chave_rejeita_vazia():
    valido, erro = des.validar_chave("")
    assert valido is False
    assert erro == "A chave não pode ser vazia."


def teste_validar_chave_rejeita_acima_de_8():
    valido, erro = des.validar_chave("123456789")
    assert valido is False, "Chave de 9 caracteres deveria ser rejeitada"


def teste_validar_chave_rejeita_nao_ascii():
    valido, erro = des.validar_chave("emoji😀")
    assert valido is False


def teste_validar_chave_normaliza_acento():
    valido, erro = des.validar_chave("café12")
    assert valido is True, f"Chave acentuada deveria ser aceita apos normalizacao: {erro}"


def teste_preparar_chave_completa_com_zeros():
    assert des._preparar_chave("ab") == b"ab\x00\x00\x00\x00\x00\x00"
    assert des._preparar_chave("12345678") == b"12345678"


def teste_cifrar_produz_base64_valido():
    resultado = des.cifrar("Ola mundo!", CHAVE_EXEMPLO)
    assert REGEX_BASE64.match(resultado), (
        f"Saida de cifrar() deveria ser Base64 puro, obtido {resultado!r}"
    )


def teste_ida_e_volta_round_trip():
    for frase in ["Ola mundo!", "a", "Teste, 1 2 3.", "Mensagem maior que um bloco de oito bytes"]:
        cifrado = des.cifrar(frase, CHAVE_EXEMPLO)
        decifrado = des.decifrar(cifrado, CHAVE_EXEMPLO)
        assert decifrado == frase, f"{frase!r} -> {cifrado!r} -> {decifrado!r}"


def teste_ida_e_volta_com_chave_curta():
    cifrado = des.cifrar("mensagem qualquer", "ab")
    decifrado = des.decifrar(cifrado, "ab")
    assert decifrado == "mensagem qualquer"


def teste_texto_vazio_produz_criptograma_vazio():
    assert des.cifrar("", CHAVE_EXEMPLO) == ""
    assert des.decifrar("", CHAVE_EXEMPLO) == ""


def teste_chave_errada_nao_recupera_o_texto():
    # Chave de 8 caracteres (limite de TAMANHO_BLOCO) -- validar_chave()
    # aceita, entao _preparar_chave() nao levanta ValueError aqui.
    cifrado = des.cifrar("MENSAGEM SECRETA", CHAVE_EXEMPLO)
    resultado = des.decifrar(cifrado, "outrach1")
    assert resultado != "MENSAGEM SECRETA"


def teste_decifrar_com_chave_errada_nao_derruba_o_cliente():
    # Mesma observacao: chave de 8 caracteres, dentro do limite aceito por
    # validar_chave() -- o ponto do teste e' verificar que uma chave ERRADA
    # (mas valida) nao derruba decifrar(), nao testar chave invalida (isso
    # e' responsabilidade de validar_chave(), ja coberto por outro teste).
    cifrado = des.cifrar("Ola, tudo bem?", CHAVE_EXEMPLO)
    try:
        resultado = des.decifrar(cifrado, "diferent")
    except Exception as e:
        assert False, f"decifrar() com chave errada nao deveria lancar excecao: {e}"
    assert isinstance(resultado, str)


def teste_decifrar_lixo_nao_derruba_o_cliente():
    for entrada in ["não é base64!!!", "===", "!!!", "OLA MUNDO"]:
        try:
            resultado = des.decifrar(entrada, CHAVE_EXEMPLO)
        except Exception as e:
            assert False, f"decifrar({entrada!r}) nao deveria lancar excecao: {e}"
        assert isinstance(resultado, str)


def teste_bytes_brutos_bate_com_cifrar():
    cifrado_base64 = des.cifrar("Ola, tudo bem?", CHAVE_EXEMPLO)
    esperado = base64.b64decode(cifrado_base64)
    obtido = des.bytes_brutos(cifrado_base64)
    assert obtido == esperado


def teste_cifrar_com_chave_vazia_estoura_valueerror_claro():
    try:
        des.cifrar("mensagem", "")
    except ValueError as e:
        assert "vazia" in str(e).lower(), f"erro pouco claro para chave vazia: {e}"
    else:
        assert False, "cifrar() aceitou chave vazia em silencio"


def teste_validar_chave_aceita_hexadecimal_do_slide():
    # Chave do slide "DES - Aplicacao": 16 digitos hexadecimais = 8 bytes.
    for chave in ["0123456789ABCDEF", "01 23 45 67 89 AB CD EF", "0123456789abcdef"]:
        valido, erro = des.validar_chave(chave)
        assert valido is True, f"Chave hexadecimal {chave!r} foi rejeitada: {erro}"


def teste_preparar_chave_hexadecimal_vira_bytes_crus():
    esperado = bytes.fromhex("0123456789ABCDEF")
    assert des._preparar_chave("0123456789ABCDEF") == esperado
    assert des._preparar_chave("01 23 45 67 89 AB CD EF") == esperado


def teste_cifrar_com_chave_hexadecimal_bate_com_slide():
    cifrado = des.cifrar("Atacar base norte.", "01 23 45 67 89 AB CD EF")
    esperado = bytes.fromhex("3044351B5A18C03DEF5FE56B50211EF3DF4EE0859A96E988")
    assert base64.b64decode(cifrado) == esperado
    assert des.decifrar(cifrado, "0123456789ABCDEF") == "Atacar base norte."


def teste_validar_chave_rejeita_hexadecimal_incompleto():
    valido, erro = des.validar_chave("0123456789ABCDE")  # 15 digitos
    assert valido is False


TESTES = [
    teste_bytes_para_bits_e_volta,
    teste_permutar_tabela_simples,
    teste_deslocar_esquerda,
    teste_xor,
    teste_ip_exemplo_pdf,
    teste_subchaves_vetor_classico_livro_texto,
    teste_subchaves_exemplo_atacar_base_norte,
    teste_expansao_e_sbox_exemplo_pdf,
    teste_rodadas_1_a_3_exemplo_pdf,
    teste_bloco_vetor_classico_livro_texto,
    teste_bloco_exemplo_atacar_base_norte,
    teste_mensagem_completa_exemplo_pdf,
    teste_validar_chave_aceita_ate_8_caracteres,
    teste_validar_chave_aceita_curta,
    teste_validar_chave_rejeita_vazia,
    teste_validar_chave_rejeita_acima_de_8,
    teste_validar_chave_rejeita_nao_ascii,
    teste_validar_chave_normaliza_acento,
    teste_preparar_chave_completa_com_zeros,
    teste_validar_chave_aceita_hexadecimal_do_slide,
    teste_preparar_chave_hexadecimal_vira_bytes_crus,
    teste_cifrar_com_chave_hexadecimal_bate_com_slide,
    teste_validar_chave_rejeita_hexadecimal_incompleto,
    teste_cifrar_produz_base64_valido,
    teste_ida_e_volta_round_trip,
    teste_ida_e_volta_com_chave_curta,
    teste_texto_vazio_produz_criptograma_vazio,
    teste_chave_errada_nao_recupera_o_texto,
    teste_decifrar_com_chave_errada_nao_derruba_o_cliente,
    teste_decifrar_lixo_nao_derruba_o_cliente,
    teste_bytes_brutos_bate_com_cifrar,
    teste_cifrar_com_chave_vazia_estoura_valueerror_claro,
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
