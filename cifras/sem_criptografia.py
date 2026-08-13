"""
Contrato obrigatório que TODOS módulos de cifra em cifras/ deve implementar:

    validar_chave(chave: str) -> tuple[bool, str]
        Retorna (True, "") se a chave for aceitável para esta cifra.
        Retorna (False, "motivo do erro") caso contrário.
        Se a cifra não usa chave (como esta), sempre retornar (True, "").

    cifrar(texto: str, chave: str) -> str
        Recebe texto em claro e a chave já validada. Retorna o texto cifrado.

    decifrar(texto: str, chave: str) -> str
        Recebe texto cifrado e a mesma chave. Retorna o texto em claro.

Regras gerais (seção 5 do enunciado):
    - Nesta opção (sem criptografia), o texto NÃO deve ser normalizado.
    - Nas outras cifras: maiúsculas, remoção de acentos, Ç -> C,
      espaços/números/pontuação preservados (exceto Playfair, que tem
      normalização própria).
"""

def validar_chave(chave: str) -> tuple[bool, str]:
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    return texto

def decifrar(texto: str, chave: str) -> str:
    return texto