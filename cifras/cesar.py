"""
Cifra de César.
Chave: inteiro entre 0 e 25.
C = (P + chave) mod 26   |   P = (C - chave + 26) mod 26
Normalização: maiúsculas, sem acento, Ç -> C, demais caracteres inalterados.
"""

def validar_chave(chave: str) -> tuple[bool, str]:
    if not chave.isdigit():
        return False, "A chave deve ser um número inteiro."
    valor = int(chave)
    if not (0 <= valor <= 25):
        return False, "A chave deve estar entre 0 e 25."
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    # TODO: normalizar texto e aplicar deslocamento
    raise NotImplementedError

def decifrar(texto: str, chave: str) -> str:
    # TODO: aplicar deslocamento inverso
    raise NotImplementedError