"""
Cifra de Playfair.
Chave: palavra/expressão em letras (J normalizado para I).
Matriz 5x5. Mensagem separada em pares, com regras de preenchimento com X.
"""

def validar_chave(chave: str) -> tuple[bool, str]:
    letras = [c for c in chave.upper() if c.isalpha()]
    if not letras:
        return False, "A chave deve conter ao menos uma letra."
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    # TODO: montar matriz 5x5, normalizar mensagem em pares, aplicar regras de linha/coluna/retângulo
    raise NotImplementedError

def decifrar(texto: str, chave: str) -> str:
    # TODO: inverso das regras de cifrar
    raise NotImplementedError