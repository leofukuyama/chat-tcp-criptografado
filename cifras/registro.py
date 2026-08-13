from cifras import sem_criptografia, cesar, monoalfabetica, playfair, vigenere

CIFRAS = {
    "1": sem_criptografia,
    "2": cesar,
    "3": monoalfabetica,
    "4": playfair,
    "5": vigenere,
}

NOMES = {
    "1": "Sem criptografia",
    "2": "Cifra de César",
    "3": "Cifra monoalfabética",
    "4": "Cifra de Playfair",
    "5": "Cifra de Vigenère",
}