"""
Testes isolados da Cifra Monoalfabética -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_monoalfabetica.py  (a partir da raiz do projeto)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import monoalfabetica

CHAVE_EXEMPLO = "QWERTYUIOPASDFGHJKLZXCVBNM"  # exemplo direto do enunciado


def teste_validar_chave_aceita_permutacao_valida():
    valido, erro = monoalfabetica.validar_chave(CHAVE_EXEMPLO)
    assert valido is True, f"Chave válida do enunciado foi rejeitada: {erro}"


def teste_validar_chave_rejeita_tamanho_errado():
    valido, erro = monoalfabetica.validar_chave("ABC")
    assert valido is False, "Chave curta deveria ser rejeitada"

    valido, erro = monoalfabetica.validar_chave(CHAVE_EXEMPLO + "A")
    assert valido is False, "Chave com 27 letras deveria ser rejeitada"


def teste_validar_chave_rejeita_letras_repetidas():
    chave_com_repeticao = "AABCDEFGHIJKLMNOPQRSTUVWX"  # 26 chars, mas com repetição
    valido, erro = monoalfabetica.validar_chave(chave_com_repeticao)
    assert valido is False, "Chave com letra repetida deveria ser rejeitada"


def teste_validar_chave_rejeita_numeros_e_simbolos():
    chave_invalida = "QWERTYUIOPASDFGHJKLZXCVB1M"
    valido, erro = monoalfabetica.validar_chave(chave_invalida)
    assert valido is False, "Chave com número deveria ser rejeitada"


def teste_validar_chave_aceita_minuscula_e_normaliza():
    chave_minuscula = CHAVE_EXEMPLO.lower()
    valido, erro = monoalfabetica.validar_chave(chave_minuscula)
    assert valido is True, "Chave em minúsculas deveria ser aceita (normalizada internamente)"


def teste_cifrar_exemplo_do_enunciado():
    # A->Q, B->W, C->E, conforme exemplo da seção 4 do enunciado
    resultado = monoalfabetica.cifrar("ABC", CHAVE_EXEMPLO)
    assert resultado == "QWE", f"Esperado QWE, obtido {resultado}"


def teste_cifrar_normaliza_para_maiuscula():
    resultado = monoalfabetica.cifrar("abc", CHAVE_EXEMPLO)
    assert resultado == "QWE", f"Deveria normalizar para maiúscula antes de cifrar, obtido {resultado}"


def teste_cifrar_remove_acentos():
    # á -> A -> (mapeado pela chave) -> Q
    resultado = monoalfabetica.cifrar("á", CHAVE_EXEMPLO)
    assert resultado == "Q", f"Acento deveria ser removido antes de cifrar, obtido {resultado}"


def teste_cifrar_trata_cedilha_como_c():
    # ç -> C -> (mapeado pela chave) -> E
    resultado = monoalfabetica.cifrar("ç", CHAVE_EXEMPLO)
    assert resultado == "E", f"Ç deveria ser tratado como C, obtido {resultado}"


def teste_cifrar_preserva_espacos_numeros_pontuacao():
    resultado = monoalfabetica.cifrar("A 1, B!", CHAVE_EXEMPLO)
    assert resultado == "Q 1, W!", f"Espaços/números/pontuação não deveriam ser alterados, obtido {resultado}"


def teste_ida_e_volta_round_trip():
    original = "Café às 15h?"
    cifrado = monoalfabetica.cifrar(original, CHAVE_EXEMPLO)
    decifrado = monoalfabetica.decifrar(cifrado, CHAVE_EXEMPLO)

    esperado_normalizado = "CAFE AS 15H?"
    assert decifrado == esperado_normalizado, (
        f"Esperado {esperado_normalizado}, obtido {decifrado}"
    )


def teste_cifra_e_decifra_sao_inversas_para_todo_alfabeto():
    """Testa a permutação completa A-Z, garantindo que o mapa e seu inverso batem."""
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cifrado = monoalfabetica.cifrar(alfabeto, CHAVE_EXEMPLO)
    assert cifrado == CHAVE_EXEMPLO, (
        f"Cifrar o alfabeto inteiro deveria produzir a própria chave, obtido {cifrado}"
    )

    decifrado = monoalfabetica.decifrar(cifrado, CHAVE_EXEMPLO)
    assert decifrado == alfabeto, (
        f"Decifrar deveria recuperar o alfabeto original, obtido {decifrado}"
    )


def teste_chave_acentuada_nao_vaza_para_a_cifra():
    """Regressão: validar_chave() normaliza a chave antes de validar, então
    'Ñ' é aceito no lugar de 'N'. Se cifrar() usasse a chave CRUA, a letra
    mapeada para 'Ñ' produziria uma cifra não-ASCII, impossível de
    transmitir -- e o usuário só descobriria ao tentar mandar a mensagem.
    Chave e texto precisam sofrer a MESMA normalização."""
    chave_acentuada = "QWERTYUIOPASDFGHJKLZXCVBÑM"

    valido, _ = monoalfabetica.validar_chave(chave_acentuada)
    assert valido is True, "chave acentuada deveria ser aceita apos normalizacao"

    # 'Y' e a letra mapeada para a posicao onde esta o 'Ñ'
    cifrado = monoalfabetica.cifrar("YAYA COM ESTILO", chave_acentuada)
    assert cifrado.isascii(), (
        f"cifrar() com chave acentuada gerou saida nao-ASCII: {cifrado!r}"
    )

    assert monoalfabetica.decifrar(cifrado, chave_acentuada) == "YAYA COM ESTILO", (
        "a chave acentuada deve decifrar igual a sua versao sem acento"
    )


def teste_chave_acentuada_equivale_a_chave_sem_acento():
    acentuada = "QWERTYUIOPASDFGHJKLZXCVBÑM"
    limpa = "QWERTYUIOPASDFGHJKLZXCVBNM"
    assert monoalfabetica.cifrar("ATAQUE", acentuada) == monoalfabetica.cifrar("ATAQUE", limpa)


def rodar_todos():
    testes = [
        teste_chave_acentuada_nao_vaza_para_a_cifra,
        teste_chave_acentuada_equivale_a_chave_sem_acento,
        teste_validar_chave_aceita_permutacao_valida,
        teste_validar_chave_rejeita_tamanho_errado,
        teste_validar_chave_rejeita_letras_repetidas,
        teste_validar_chave_rejeita_numeros_e_simbolos,
        teste_validar_chave_aceita_minuscula_e_normaliza,
        teste_cifrar_exemplo_do_enunciado,
        teste_cifrar_normaliza_para_maiuscula,
        teste_cifrar_remove_acentos,
        teste_cifrar_trata_cedilha_como_c,
        teste_cifrar_preserva_espacos_numeros_pontuacao,
        teste_ida_e_volta_round_trip,
        teste_cifra_e_decifra_sao_inversas_para_todo_alfabeto,
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