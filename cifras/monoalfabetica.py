"""
Cifra monoalfabética.
Chave: permutação das 26 letras (sem repetição), ex: QWERTYUIOPASDFGHJKLZXCVBNM
"""

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def validar_chave(chave: str) -> tuple[bool, str]:
    chave = chave.upper()
    if len(chave) != 26:
        return False, "A chave deve ter exatamente 26 letras."
    if len(set(chave)) != 26:
        return False, "A chave não pode ter letras repetidas."
    if not chave.isalpha():
        return False, "A chave deve conter apenas letras."
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    # TODO: normalizar texto e substituir cada letra pela correspondente na chave
    raise NotImplementedError

def decifrar(texto: str, chave: str) -> str:
    # TODO: substituição inversa
    raise NotImplementedError