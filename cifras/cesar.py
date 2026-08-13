"""
Cifra de César.
Chave: inteiro entre 0 e 25.
C = (P + chave) mod 26   |   P = (C - chave + 26) mod 26
Normalização: maiúsculas, sem acento, Ç -> C, demais caracteres inalterados.
"""

import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def validar_chave(chave: str) -> tuple[bool, str]:
    if not chave.isdigit():
        return False, "A chave deve ser um número inteiro."
    valor = int(chave)
    if not (0 <= valor <= 25):
        return False, "A chave deve estar entre 0 e 25."
    return True, ""


def _normalizar(texto: str) -> str:
    """
    Aplica as regras de normalização do enunciado (seção 5):
      - maiúsculas
      - Ç -> C (feito ANTES da remoção de acento, pois a cedilha some
        junto com os acentos no processo de decomposição Unicode)
      - remoção de acentos (Á -> A, É -> E, ...)
      - espaços, números e pontuação permanecem inalterados
    """
    texto = texto.upper()
    texto = texto.replace("Ç", "C")

    # NFD decompõe cada caractere acentuado em "letra base" + "acento
    # combinante" (ex: "Á" -> "A" + acento). Filtrando fora tudo que é
    # marca de acentuação (categoria Unicode "Mn"), sobra só a letra base.
    texto_decomposto = unicodedata.normalize("NFD", texto)
    texto_sem_acento = "".join(
        c for c in texto_decomposto if unicodedata.category(c) != "Mn"
    )
    return texto_sem_acento


def cifrar(texto: str, chave: str) -> str:
    """
    Encripta uma string usando a Cifra de César.
    """
    deslocamento = int(chave)  # a chave chega como string; precisa virar int
    texto_normalizado = _normalizar(texto)

    resultado = ""
    for char in texto_normalizado:
        if char in ALFABETO:
            posicao = ALFABETO.index(char)
            nova_posicao = (posicao + deslocamento) % 26
            resultado += ALFABETO[nova_posicao]
        else:
            # espaço, número, pontuação: não é letra, não desloca
            resultado += char

    return resultado


def decifrar(texto: str, chave: str) -> str:
    """
    Decripta uma string usando a Cifra de César.
    Reaproveita cifrar() aplicando o deslocamento inverso (negativo) --
    o operador módulo do Python sempre devolve resultado não-negativo
    quando o divisor é positivo, então a fórmula funciona igual.

    IMPORTANTE: não normaliza de novo aqui. O texto recebido já é o
    texto CIFRADO (já normalizado quando foi cifrado do outro lado);
    normalizar de novo seria reprocessar como se fosse entrada nova,
    o que é conceitualmente errado para uma função de decifragem.
    """
    deslocamento_invertido = str(-int(chave))
    return cifrar(texto, deslocamento_invertido)