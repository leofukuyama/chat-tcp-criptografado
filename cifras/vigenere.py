"""
Cifra de Vigenère.
Chave: palavra só de letras, repetida ao longo da mensagem.
Espaços/pontuação não avançam a chave.
C = (P + K) mod 26   |   P = (C - K + 26) mod 26
"""

def validar_chave(chave: str) -> tuple[bool, str]:
    if not chave:
        return False, "A chave não pode ser vazia."
    if not chave.isalpha():
        return False, "A chave deve conter apenas letras."
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    # TODO: normalizar texto; avançar a chave apenas ao processar uma letra
    raise NotImplementedError

def decifrar(texto: str, chave: str) -> str:
    # TODO: inverso
    raise NotImplementedError