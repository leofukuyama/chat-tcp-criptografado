"""
Testes isolados da Cifra DES -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_des.py  (a partir da raiz do projeto)
"""

import os
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


TESTES = [
    teste_bytes_para_bits_e_volta,
    teste_permutar_tabela_simples,
    teste_deslocar_esquerda,
    teste_xor,
    teste_ip_exemplo_pdf,
    teste_subchaves_vetor_classico_livro_texto,
    teste_subchaves_exemplo_atacar_base_norte,
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
