"""
Testes isolados da Cifra de César -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_cesar.py  (a partir da raiz do projeto)
"""

import os
import sys

# Garante que o pacote cifras/ seja encontrado mesmo rodando este arquivo
# diretamente de dentro da pasta tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import cesar


def teste_validar_chave_aceita_valores_no_intervalo():
    valido, erro = cesar.validar_chave("0")
    assert valido is True, "Chave 0 deveria ser válida (limite inferior)"

    valido, erro = cesar.validar_chave("25")
    assert valido is True, "Chave 25 deveria ser válida (limite superior)"

    valido, erro = cesar.validar_chave("13")
    assert valido is True, "Chave 13 deveria ser válida"


def teste_validar_chave_rejeita_fora_do_intervalo():
    valido, erro = cesar.validar_chave("26")
    assert valido is False, "Chave 26 deveria ser rejeitada (fora do intervalo 0-25)"
    assert erro != ""

    valido, erro = cesar.validar_chave("-1")
    assert valido is False, "Chave negativa deveria ser rejeitada"


def teste_validar_chave_rejeita_nao_numerico():
    valido, erro = cesar.validar_chave("abc")
    assert valido is False, "Chave não numérica deveria ser rejeitada"

    valido, erro = cesar.validar_chave("")
    assert valido is False, "Chave vazia deveria ser rejeitada"

    valido, erro = cesar.validar_chave("12.5")
    assert valido is False, "Chave decimal deveria ser rejeitada"


def teste_cifrar_exemplo_do_enunciado():
    # Exemplo direto da seção 4 do enunciado: chave 3, OLA -> ROD
    resultado = cesar.cifrar("OLA", "3")
    assert resultado == "ROD", f"Esperado ROD, obtido {resultado}"


def teste_decifrar_exemplo_do_enunciado():
    resultado = cesar.decifrar("ROD", "3")
    assert resultado == "OLA", f"Esperado OLA, obtido {resultado}"


def teste_cifrar_normaliza_para_maiuscula():
    resultado = cesar.cifrar("ola", "3")
    assert resultado == "ROD", f"Deveria normalizar para maiúscula antes de cifrar, obtido {resultado}"


def teste_cifrar_remove_acentos():
    # á -> A -> (cifrado com chave 1) -> B
    resultado = cesar.cifrar("á", "1")
    assert resultado == "B", f"Acento deveria ser removido antes de cifrar, obtido {resultado}"


def teste_cifrar_trata_cedilha_como_c():
    # ç -> C -> (cifrado com chave 1) -> D
    resultado = cesar.cifrar("ç", "1")
    assert resultado == "D", f"Ç deveria ser tratado como C, obtido {resultado}"


def teste_cifrar_preserva_espacos_numeros_pontuacao():
    resultado = cesar.cifrar("A 1, B!", "1")
    assert resultado == "B 1, C!", f"Espaços/números/pontuação não deveriam ser deslocados, obtido {resultado}"


def teste_cifrar_com_wraparound_no_fim_do_alfabeto():
    # Z + chave 1 deve voltar para A (mod 26)
    resultado = cesar.cifrar("Z", "1")
    assert resultado == "A", f"Deveria dar wraparound de Z para A, obtido {resultado}"


def teste_cifrar_com_chave_zero_nao_altera_letras():
    resultado = cesar.cifrar("ABC", "0")
    assert resultado == "ABC", f"Chave 0 não deveria alterar nada, obtido {resultado}"


def teste_ida_e_volta_round_trip():
    """
    Cifrar e depois decifrar deve retornar ao texto NORMALIZADO original
    (não ao texto digitado originalmente, já que a normalização é
    irreversível por natureza -- ver observação sobre isso na aula).
    """
    original = "Olá, tudo bem? Ligo às 15h."
    chave = "7"

    cifrado = cesar.cifrar(original, chave)
    decifrado = cesar.decifrar(cifrado, chave)

    esperado_normalizado = "OLA, TUDO BEM? LIGO AS 15H."
    assert decifrado == esperado_normalizado, (
        f"Esperado {esperado_normalizado}, obtido {decifrado}"
    )


def teste_ida_e_volta_para_todas_as_chaves_possiveis():
    """Garante que a fórmula funciona para toda a faixa válida de chave (0-25)."""
    original = "TESTE COMPLETO DE TODAS AS CHAVES"
    for chave in range(26):
        cifrado = cesar.cifrar(original, str(chave))
        decifrado = cesar.decifrar(cifrado, str(chave))
        assert decifrado == original, (
            f"Falhou no round-trip com chave {chave}: obtido {decifrado}"
        )


def rodar_todos():
    testes = [
        teste_validar_chave_aceita_valores_no_intervalo,
        teste_validar_chave_rejeita_fora_do_intervalo,
        teste_validar_chave_rejeita_nao_numerico,
        teste_cifrar_exemplo_do_enunciado,
        teste_decifrar_exemplo_do_enunciado,
        teste_cifrar_normaliza_para_maiuscula,
        teste_cifrar_remove_acentos,
        teste_cifrar_trata_cedilha_como_c,
        teste_cifrar_preserva_espacos_numeros_pontuacao,
        teste_cifrar_com_wraparound_no_fim_do_alfabeto,
        teste_cifrar_com_chave_zero_nao_altera_letras,
        teste_ida_e_volta_round_trip,
        teste_ida_e_volta_para_todas_as_chaves_possiveis,
    ]

    falhas = 0
    for teste in testes:
        try:
            teste()
            print(f"[OK]    {teste.__name__}")
        except AssertionError as e:
            falhas += 1
            print(f"[FALHA] {teste.__name__} -- {e}")

    print(f"\n{len(testes) - falhas}/{len(testes)} testes passaram.")
    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()