def cifra_cesar_encriptar(texto, deslocamento):
    """
    Encripta uma string usando a Cifra de César.
    """
    resultado = ""
    for char in texto:
        # Verifica se é uma letra do alfabeto
        if char.isalpha():
            # Define a base ASCII dependendo se é maiúscula ou minúscula
            ascii_base = ord('A') if char.isupper() else ord('a')
            
            # Aplica o deslocamento e garante que volte ao início do alfabeto se passar de 'Z' ou 'z'
            novo_char = chr((ord(char) - ascii_base + deslocamento) % 26 + ascii_base)
            resultado += novo_char
        else:
            # Mantém espaços, números e pontuação inalterados
            resultado += char
            
    return resultado

def cifra_cesar_decriptar(texto, deslocamento):
    """
    Decripta uma string usando a Cifra de César.
    Basta aplicar o deslocamento inverso (negativo).
    """
    return cifra_cesar_encriptar(texto, -deslocamento)
