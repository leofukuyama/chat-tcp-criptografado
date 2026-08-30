"""
Testes isolados da Cifra de Vigenère -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_vigenere.py  (a partir da raiz do projeto)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import vigenere

CHAVE_EXEMPLO = "GANHA"  # exemplo usado ao longo da conversa/enunciado


def teste_validar_chave_aceita_chave_valida():
    valido, erro = vigenere.validar_chave(CHAVE_EXEMPLO)
    assert valido is True, f"Chave válida foi rejeitada: {erro}"


def teste_validar_chave_rejeita_vazia():
    valido, erro = vigenere.validar_chave("")
    assert valido is False, "Chave vazia deveria ser rejeitada"
    assert erro == "A chave não pode ser vazia."


def teste_validar_chave_rejeita_numeros_e_simbolos():
    valido, erro = vigenere.validar_chave("GAN1A")
    assert valido is False, "Chave com número deveria ser rejeitada"

    valido, erro = vigenere.validar_chave("GAN!A")
    assert valido is False, "Chave com símbolo deveria ser rejeitada"


def teste_validar_chave_aceita_minuscula():
    valido, erro = vigenere.validar_chave("ganha")
    assert valido is True, "Chave em minúsculas deveria ser aceita"


def teste_cifrar_exemplo_do_enunciado():
    # T->Z, I->I, M->Z, A->H, O->O, conforme cálculo manual TIMAO + GANHA
    resultado = vigenere.cifrar("TIMAO", CHAVE_EXEMPLO)
    assert resultado == "ZIZHO", f"Esperado ZIZHO, obtido {resultado}"


def teste_decifrar_exemplo_do_enunciado():
    resultado = vigenere.decifrar("ZIZHO", CHAVE_EXEMPLO)
    assert resultado == "TIMAO", f"Esperado TIMAO, obtido {resultado}"


def teste_cifrar_preserva_maiuscula_e_minuscula():
    resultado = vigenere.cifrar("Timao", CHAVE_EXEMPLO)
    assert resultado == "Zizho", f"Deveria preservar padrão de caixa, obtido {resultado}"


def teste_cifrar_remove_acentos():
    # TIMÃO normaliza para TIMAO antes de cifrar -> mesmo resultado do exemplo do enunciado
    resultado = vigenere.cifrar("TIMÃO", CHAVE_EXEMPLO)
    assert resultado == "ZIZHO", f"Acento deveria ser removido antes de cifrar, obtido {resultado}"


def teste_cifrar_trata_cedilha_como_c():
    # ç -> c -> cifrado com a primeira letra da chave (B): c(2) + B(1) = D
    resultado = vigenere.cifrar("ç", "B")
    assert resultado == "d", f"Ç deveria ser tratado como C, obtido {resultado}"


def teste_cifrar_preserva_espacos_numeros_pontuacao():
    resultado = vigenere.cifrar("A 1, B!", "B")
    assert resultado == "B 1, C!", (
        f"Espaços/números/pontuação não deveriam ser alterados, obtido {resultado}"
    )


def teste_pontuacao_nao_avanca_a_chave():
    # Com chave de 1 letra "B", pontuação/espaço não deveriam quebrar o deslocamento
    # constante aplicado a cada letra (sempre +1).
    resultado = vigenere.cifrar("A, A. A", "B")
    assert resultado == "B, B. B", (
        f"Chave de tamanho 1 deveria deslocar todas as letras igualmente, obtido {resultado}"
    )


def teste_ida_e_volta_round_trip():
    original = "Café às 15h?"
    cifrado = vigenere.cifrar(original, CHAVE_EXEMPLO)
    decifrado = vigenere.decifrar(cifrado, CHAVE_EXEMPLO)

    esperado_normalizado = "Cafe as 15h?"
    assert decifrado == esperado_normalizado, (
        f"Esperado {esperado_normalizado}, obtido {decifrado}"
    )


def teste_chave_repete_ciclicamente_em_texto_longo():
    # Chave menor que o texto deve se repetir (mod m) ao longo de todas as letras
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cifrado = vigenere.cifrar(alfabeto, "AB")

    # Com chave "AB": posições pares deslocam +0 (A), ímpares deslocam +1 (B)
    esperado = "ACCEEGGIIKKMMOOQQSSUUWWYYA"
    assert cifrado == esperado, f"Esperado {esperado}, obtido {cifrado}"

    decifrado = vigenere.decifrar(cifrado, "AB")
    assert decifrado == alfabeto, (
        f"Decifrar deveria recuperar o alfabeto original, obtido {decifrado}"
    )


def teste_vetor_canonico():
    # Vetor de referência clássico da literatura: ATTACKATDAWN + LEMON
    resultado = vigenere.cifrar("ATTACKATDAWN", "LEMON")
    assert resultado == "LXFOPVEFRNHR", f"Esperado LXFOPVEFRNHR, obtido {resultado}"
    assert vigenere.decifrar("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def teste_chave_com_acento_equivale_a_chave_sem_acento():
    # A chave é normalizada antes do cálculo, então "AÇÃO" e "ACAO" cifram igual
    assert vigenere.cifrar("MENSAGEM", "AÇÃO") == vigenere.cifrar("MENSAGEM", "ACAO")


def teste_chave_errada_nao_recupera_o_texto():
    cifrado = vigenere.cifrar("MENSAGEM SECRETA", CHAVE_EXEMPLO)
    assert vigenere.decifrar(cifrado, "OUTRA") != "MENSAGEM SECRETA", (
        "Decifrar com a chave errada não deveria devolver o texto original"
    )


def teste_round_trip_de_frases_ascii():
    for frase in ["Ola mundo!", "Reuniao as 15h.", "a", "Teste, 1 2 3."]:
        cifrado = vigenere.cifrar(frase, CHAVE_EXEMPLO)
        assert vigenere.decifrar(cifrado, CHAVE_EXEMPLO) == frase, (
            f"{frase!r} -> {cifrado!r} -> {vigenere.decifrar(cifrado, CHAVE_EXEMPLO)!r}"
        )


# --------------------------------------------------------------------
# DIAGNÓSTICO -- defeitos confirmados (falham hoje)
# --------------------------------------------------------------------

def diag_letra_cujo_upper_expande():
    """cifrar() assume que letra.upper() devolve 1 caractere, mas alguns
    caracteres expandem: 'ß'.upper() == 'SS'. ord() recebe 2 caracteres e
    levanta TypeError -- ou seja, digitar 'ß' no chat derruba o cliente."""
    try:
        vigenere.cifrar("Straße", CHAVE_EXEMPLO)
    except TypeError as e:
        assert False, f"cifrar() estourou TypeError com letra que expande no upper(): {e}"


def diag_letra_alfabetica_fora_de_az():
    """isalpha() é verdadeiro para qualquer letra Unicode, não só A-Z.
    'Ω' (ord 937) entra na conta como se fosse uma letra do alfabeto
    latino e sai como uma letra ASCII qualquer -- perda silenciosa de
    dados, o texto decifrado nunca volta ao original."""
    original = "Omega Ω"
    decifrado = vigenere.decifrar(vigenere.cifrar(original, "A"), "A")
    assert decifrado == original, f"{original!r} -> {decifrado!r} (letra fora de A-Z corrompida)"


def diag_validar_chave_aceita_letra_fora_de_az():
    """validar_chave() usa isalpha(), então aceita chaves em alfabetos que
    a cifra não sabe tratar (grego, cirílico). O deslocamento resultante
    não corresponde a nenhuma letra de A-Z."""
    valido, _ = vigenere.validar_chave("Ω")
    assert valido is False, "Chave fora de A-Z deveria ser rejeitada pela validação"


def diag_cifrar_com_chave_vazia_estoura():
    """As funções precisam se defender sozinhas, sem depender de o chamador
    ter passado por validar_chave() antes.

    Antes, chave vazia dava ZeroDivisionError em 'j % len(chave)' -- um
    erro que não diz nada sobre a causa. O esperado é um ValueError
    explicando o problema, que é o que validar_chave() já respondia."""
    try:
        vigenere.cifrar("ATAQUE", "")
    except ZeroDivisionError:
        assert False, "cifrar() com chave vazia estourou ZeroDivisionError em vez de erro claro"
    except ValueError as e:
        assert "vazia" in str(e).lower(), f"erro pouco claro para chave vazia: {e}"
    else:
        assert False, "cifrar() aceitou chave vazia em silêncio"


TESTES = [
    teste_validar_chave_aceita_chave_valida,
    teste_validar_chave_rejeita_vazia,
    teste_validar_chave_rejeita_numeros_e_simbolos,
    teste_validar_chave_aceita_minuscula,
    teste_cifrar_exemplo_do_enunciado,
    teste_decifrar_exemplo_do_enunciado,
    teste_cifrar_preserva_maiuscula_e_minuscula,
    teste_cifrar_remove_acentos,
    teste_cifrar_trata_cedilha_como_c,
    teste_cifrar_preserva_espacos_numeros_pontuacao,
    teste_pontuacao_nao_avanca_a_chave,
    teste_ida_e_volta_round_trip,
    teste_chave_repete_ciclicamente_em_texto_longo,
    teste_vetor_canonico,
    teste_chave_com_acento_equivale_a_chave_sem_acento,
    teste_chave_errada_nao_recupera_o_texto,
    teste_round_trip_de_frases_ascii,
]

DIAGNOSTICO = [
    diag_letra_cujo_upper_expande,
    diag_letra_alfabetica_fora_de_az,
    diag_validar_chave_aceita_letra_fora_de_az,
    diag_cifrar_com_chave_vazia_estoura,
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

    print("\n--- diagnóstico de casos-limite (defeitos conhecidos) ---")
    bugs = 0
    for teste in DIAGNOSTICO:
        try:
            teste()
            print(f"[OK]    {teste.__name__} (defeito parece corrigido)")
        except AssertionError as e:
            bugs += 1
            print(f"[BUG]   {teste.__name__} -- {e}")
    print(f"{bugs}/{len(DIAGNOSTICO)} defeitos ainda presentes.")

    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()