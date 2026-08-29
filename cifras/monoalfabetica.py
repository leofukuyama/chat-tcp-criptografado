"""
Cifra monoalfabética.
Chave: permutação das 26 letras (sem repetição), ex: QWERTYUIOPASDFGHJKLZXCVBNM
Normalização: maiúsculas, sem acento, Ç -> C, demais caracteres inalterados.
"""

import string

import ascii_puro

ALFABETO = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def validar_chave(chave: str) -> tuple[bool, str]:
    # Normaliza antes de validar para que "cháve" acentuada seja aceita --
    # é o mesmo tratamento que cifrar() dá ao texto.
    chave = ascii_puro.normalizar(chave).upper()

    if len(chave) != 26:
        return False, "A chave precisa ter exatamente 26 letras."

    # Checagem contra A-Z explicitamente, e não isalpha(): isalpha() é
    # verdadeiro para QUALQUER letra Unicode, então aceitaria uma chave em
    # grego ou cirílico -- alfabetos que esta cifra não sabe mapear.
    if any(c not in ALFABETO for c in chave):
        return False, "A chave só pode conter letras de A a Z."

    if len(set(chave)) != 26:
        return False, "A chave não pode ter letras repetidas."

    return True, ""


def _normalizar(texto: str) -> str:
    """
    Mesma regra usada em cesar.py (seção 5 do enunciado):
      - remoção de acentos e Ç -> C
      - maiúsculas
      - espaços, números e pontuação inalterados
    """
    return ascii_puro.normalizar(texto).upper()


def cifrar(texto: str, chave: str) -> str:
    chave = chave.upper()
    texto_normalizado = _normalizar(texto)

    tabela = str.maketrans(ALFABETO, chave)
    return texto_normalizado.translate(tabela)


def decifrar(texto: str, chave: str) -> str:
    """
    Reaproveita a mesma técnica de tradução, com o mapa invertido
    (chave -> alfabeto em vez de alfabeto -> chave).

    Não normaliza aqui: o texto recebido já é o texto CIFRADO, já
    normalizado quando foi cifrado do outro lado.
    """
    chave = chave.upper()

    tabela = str.maketrans(chave, ALFABETO)
    return texto.translate(tabela)