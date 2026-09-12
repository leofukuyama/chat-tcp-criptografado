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


TESTES = [
    teste_bytes_para_bits_e_volta,
    teste_permutar_tabela_simples,
    teste_deslocar_esquerda,
    teste_xor,
    teste_ip_exemplo_pdf,
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
