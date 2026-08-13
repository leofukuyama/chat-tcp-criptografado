"""
Cifra monoalfabética.
Chave: permutação das 26 letras (sem repetição), ex: QWERTYUIOPASDFGHJKLZXCVBNM
Normalização: maiúsculas, sem acento, Ç -> C, demais caracteres inalterados.
"""

import string
import unicodedata

ALFABETO = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def validar_chave(chave: str) -> tuple[bool, str]:
    chave = chave.upper()

    if len(chave) != 26:
        return False, "A chave precisa ter exatamente 26 letras."

    if not chave.isalpha():
        return False, "A chave não pode conter números ou símbolos."

    if len(set(chave)) != 26:
        return False, "A chave não pode ter letras repetidas."

    return True, ""


def _normalizar(texto: str) -> str:
    """
    Mesma regra usada em cesar.py (seção 5 do enunciado):
      - maiúsculas
      - Ç -> C (antes da remoção de acento)
      - remoção de acentos
      - espaços, números e pontuação inalterados
    """
    texto = texto.upper()
    texto = texto.replace("Ç", "C")

    texto_decomposto = unicodedata.normalize("NFD", texto)
    texto_sem_acento = "".join(
        c for c in texto_decomposto if unicodedata.category(c) != "Mn"
    )
    return texto_sem_acento


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