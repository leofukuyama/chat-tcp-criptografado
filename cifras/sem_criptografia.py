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

Extensão OPCIONAL do contrato (só para exibição/depuração, não é exigida):

    bytes_brutos(texto_cifrado: str) -> bytes
        Só faz sentido para cifras cujo criptograma não é ASCII "de
        fábrica" e por isso precisa de uma camada extra de codificação de
        transporte (hoje, só cifras/rc4.py -- Base64). Devolve os bytes
        crus antes dessa codificação, para comparar com formatos externos
        (ex.: um gabarito de teste em decimal) ou mostrar no chat.
        Chamadores devem testar `hasattr(modulo, "bytes_brutos")` antes de
        usar -- as outras cifras não implementam isto porque o próprio
        criptograma já é diretamente exibível.
"""

def validar_chave(chave: str) -> tuple[bool, str]:
    return True, ""

def cifrar(texto: str, chave: str) -> str:
    return texto

def decifrar(texto: str, chave: str) -> str:
    return texto