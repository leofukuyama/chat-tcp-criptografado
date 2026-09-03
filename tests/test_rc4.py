"""
Testes isolados da Cifra RC4 -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_rc4.py  (a partir da raiz do projeto)
"""

import os
import re
import sys

# Garante que o pacote cifras/ seja encontrado mesmo rodando este arquivo
# diretamente de dentro da pasta tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import rc4

CHAVE_EXEMPLO = "Key"  # mesma chave dos vetores de teste canônicos abaixo

# Só os caracteres do alfabeto Base64 padrão (+ padding "=") podem aparecer
# na saída de cifrar() -- é a garantia de que o criptograma continua
# transportável pela camada ASCII do protocolo (ver protocolo.PAYLOAD_MAXIMO
# e ascii_puro.codificar()).
REGEX_BASE64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def teste_validar_chave_aceita_chave_valida():
    valido, erro = rc4.validar_chave("Senha123!")
    assert valido is True, f"Chave válida foi rejeitada: {erro}"


def teste_validar_chave_rejeita_vazia():
    valido, erro = rc4.validar_chave("")
    assert valido is False, "Chave vazia deveria ser rejeitada"
    assert erro == "A chave não pode ser vazia."


def teste_validar_chave_aceita_numeros_e_simbolos_e_espaco():
    # Ao contrário do Vigenère, RC4 não restringe a chave a A-Z: ela é
    # matéria-prima de bytes para o KSA, não um índice em um alfabeto.
    valido, erro = rc4.validar_chave("s3nh@ com espaço #1")
    assert valido is True, f"Chave alfanumérica com símbolos deveria ser aceita: {erro}"


def teste_validar_chave_rejeita_nao_ascii():
    valido, erro = rc4.validar_chave("emoji😀")
    assert valido is False, "Chave com caractere fora do ASCII deveria ser rejeitada"


def teste_validar_chave_normaliza_acento():
    # "café" normaliza para "cafe" (sem acento), que é ASCII puro -- igual
    # ao tratamento de chave das outras cifras.
    valido, erro = rc4.validar_chave("café")
    assert valido is True, f"Chave acentuada deveria ser aceita após normalização: {erro}"


def teste_validar_chave_aceita_no_limite_de_256():
    valido, erro = rc4.validar_chave("x" * 256)
    assert valido is True, "Chave de exatamente 256 caracteres deveria ser aceita"


def teste_validar_chave_rejeita_acima_de_256():
    valido, erro = rc4.validar_chave("x" * 257)
    assert valido is False, "Chave de 257 caracteres deveria ser rejeitada"


def teste_vetores_canonicos_da_literatura():
    """
    Vetores de teste amplamente citados na literatura sobre RC4 (o mesmo
    conjunto usado no artigo da Wikipedia e em implementações de
    referência). Comparar contra eles garante que o KSA/PRGA estão
    implementados corretamente, não só que cifrar/decifrar são inversos um
    do outro.
    """
    vetores = [
        ("Key", "Plaintext", "bbf316e8d940af0ad3"),
        ("Wiki", "pedia", "1021bf0420"),
        ("Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"),
    ]
    for chave, texto, hex_esperado in vetores:
        obtido = rc4._rc4_xor(texto.encode("ascii"), chave.encode("ascii")).hex()
        assert obtido == hex_esperado, (
            f"Vetor canônico falhou para chave={chave!r} texto={texto!r}: "
            f"esperado {hex_esperado}, obtido {obtido}"
        )


def teste_bytes_brutos_bate_com_rc4_xor():
    """
    bytes_brutos() é a extensão opcional do contrato usada por client.py
    para mostrar '[CIFRADO decimal]' no chat -- tem que devolver
    exatamente o mesmo criptograma que _rc4_xor() produz, só decodificado
    de volta do Base64 que cifrar() gera.
    """
    texto, chave = "Ola, tudo bem?", CHAVE_EXEMPLO  # sem acento -- normalizar() é no-op
    cifrado_base64 = rc4.cifrar(texto, chave)
    esperado = rc4._rc4_xor(texto.encode("ascii"), chave.encode("ascii"))
    obtido = rc4.bytes_brutos(cifrado_base64)
    assert obtido == esperado, f"bytes_brutos() não bate com _rc4_xor(): {obtido!r} != {esperado!r}"


def teste_bytes_brutos_nunca_lanca_excecao_com_lixo():
    for entrada in ["não é base64!!!", "", "===", "M0044algumacoisa"]:
        try:
            resultado = rc4.bytes_brutos(entrada)
        except Exception as e:
            assert False, f"bytes_brutos({entrada!r}) não deveria lançar exceção: {e}"
        assert isinstance(resultado, bytes)


def teste_vetores_da_disciplina():
    """
    Casos de teste fornecidos pelo professor (slides/arquivos .txt da
    disciplina), com o mesmo texto plano e três chaves de tamanhos bem
    diferentes (8, 97 e 253 bytes) -- cobre o KSA com chave curta, média e
    quase no limite de TAMANHO_MAXIMO_CHAVE.

    O gabarito dá o "Texto Cript." como bytes CRUS (0-255), então a
    comparação é contra rc4._rc4_xor() -- a função que faz o KSA+PRGA -- e
    não contra rc4.cifrar(), que devolve esse mesmo resultado em Base64
    (necessário para caber no transporte ASCII deste chat; ver docstring do
    módulo). As chaves são construídas a partir do ASCII fornecido, não
    digitadas na mão, para não arriscar erro de transcrição de caracteres
    especiais (backslash, aspas, chaves) nas chaves 2 e 3.
    """
    texto_plano_ascii = [
        67, 121, 98, 101, 114, 115, 101, 99, 117, 114, 105, 116, 121, 32, 109,
        101, 108, 104, 111, 114, 32, 100, 105, 115, 99, 105, 112, 108, 105,
        110, 97, 32, 100, 111, 32, 99, 117, 114, 115, 111, 46,
    ]
    texto_plano = bytes(texto_plano_ascii)
    assert texto_plano.decode("ascii") == "Cybersecurity melhor disciplina do curso."

    vetores = {
        "T1": {
            "chave_ascii": [68, 38, 79, 116, 41, 91, 89, 87],
            "esperado": [
                214, 32, 110, 109, 116, 251, 159, 133, 226, 76, 193, 253, 168,
                73, 65, 197, 82, 72, 93, 68, 250, 55, 28, 202, 59, 77, 186, 27,
                97, 24, 48, 54, 106, 38, 82, 214, 222, 20, 20, 13, 251,
            ],
        },
        "T2": {
            "chave_ascii": [
                36, 64, 67, 42, 57, 41, 54, 67, 123, 52, 94, 100, 88, 78, 119,
                62, 72, 35, 87, 44, 98, 101, 47, 92, 39, 76, 50, 112, 77, 56,
                114, 59, 74, 89, 63, 120, 125, 66, 93, 64, 65, 96, 84, 33, 113,
                63, 105, 79, 96, 61, 110, 46, 76, 103, 109, 40, 51, 122, 56,
                64, 83, 91, 117, 93, 100, 89, 49, 107, 124, 37, 82, 73, 33, 77,
                80, 45, 40, 70, 116, 90, 108, 38, 94, 51, 58, 106, 110, 75, 60,
                84, 71, 54, 91, 53, 74, 119, 125,
            ],
            "esperado": [
                84, 179, 117, 15, 203, 82, 18, 217, 141, 197, 213, 126, 47,
                255, 83, 83, 99, 47, 120, 247, 192, 203, 33, 247, 220, 192,
                213, 82, 241, 248, 166, 142, 129, 105, 50, 227, 178, 74, 181,
                144, 94,
            ],
        },
        "T3": {
            "chave_ascii": [
                33, 77, 124, 55, 115, 93, 117, 94, 123, 68, 70, 106, 94, 63,
                56, 43, 102, 76, 58, 48, 90, 33, 42, 37, 49, 80, 95, 51, 66,
                125, 57, 109, 126, 86, 48, 64, 72, 94, 81, 102, 55, 121, 38,
                90, 52, 87, 98, 62, 107, 83, 94, 84, 60, 100, 46, 36, 46, 112,
                76, 64, 82, 124, 103, 41, 120, 41, 45, 54, 40, 69, 38, 104, 37,
                84, 45, 125, 40, 87, 37, 122, 123, 85, 57, 109, 90, 122, 56,
                126, 109, 56, 66, 102, 80, 33, 99, 38, 64, 107, 55, 73, 92, 53,
                73, 126, 84, 95, 118, 68, 33, 52, 65, 62, 124, 111, 79, 91,
                125, 51, 42, 84, 124, 36, 63, 101, 126, 48, 93, 86, 53, 38,
                121, 64, 114, 49, 88, 50, 107, 43, 64, 84, 93, 106, 63, 124,
                50, 124, 81, 37, 125, 82, 44, 68, 41, 85, 112, 92, 56, 103, 77,
                59, 87, 125, 124, 55, 101, 78, 70, 107, 94, 116, 46, 104, 47,
                106, 59, 54, 35, 121, 45, 33, 116, 53, 41, 92, 94, 76, 74, 91,
                55, 83, 60, 52, 65, 44, 102, 36, 75, 115, 49, 124, 38, 115, 88,
                33, 119, 42, 71, 40, 90, 64, 105, 62, 106, 69, 62, 54, 126, 93,
                111, 65, 53, 93, 107, 39, 46, 58, 111, 61, 55, 110, 57, 104,
                41, 36, 74, 95, 33, 97, 66, 123, 78, 45, 74, 98, 49, 77, 125,
                78, 122, 68, 92, 42, 104,
            ],
            "esperado": [
                192, 115, 138, 155, 179, 72, 115, 33, 116, 105, 228, 122, 36,
                92, 74, 122, 123, 245, 202, 209, 214, 199, 4, 191, 90, 96, 21,
                15, 190, 222, 47, 58, 192, 192, 43, 10, 166, 63, 58, 96, 230,
            ],
        },
    }

    for nome, dados in vetores.items():
        chave_bytes = bytes(dados["chave_ascii"])
        esperado = bytes(dados["esperado"])
        obtido = rc4._rc4_xor(texto_plano, chave_bytes)
        assert obtido == esperado, (
            f"{nome} (chave de {len(chave_bytes)} bytes): criptograma não bate com "
            f"o gabarito da disciplina.\nesperado: {list(esperado)}\nobtido:   {list(obtido)}"
        )


def teste_cifrar_produz_base64_valido():
    resultado = rc4.cifrar("Ola mundo!", CHAVE_EXEMPLO)
    assert REGEX_BASE64.match(resultado), (
        f"Saída de cifrar() deveria ser Base64 puro (só ASCII transportável), obtido {resultado!r}"
    )


def teste_cifrar_preserva_maiuscula_minuscula_e_pontuacao():
    """
    Diferente das cifras de substituição do catálogo, RC4 não normaliza
    para maiúscula -- cada byte do texto (incluindo caixa e pontuação) é
    transformado, e o round-trip precisa devolver exatamente o que entrou
    (só sem acento, que é removido por normalizar() antes de cifrar).
    """
    original = "Reuniao as 15h, sala B!"
    cifrado = rc4.cifrar(original, CHAVE_EXEMPLO)
    decifrado = rc4.decifrar(cifrado, CHAVE_EXEMPLO)
    assert decifrado == original, f"Esperado {original!r}, obtido {decifrado!r}"


def teste_cifrar_remove_acentos():
    original = "Ação, já! Café às 15h?"
    cifrado = rc4.cifrar(original, CHAVE_EXEMPLO)
    decifrado = rc4.decifrar(cifrado, CHAVE_EXEMPLO)
    esperado_normalizado = "Acao, ja! Cafe as 15h?"
    assert decifrado == esperado_normalizado, (
        f"Esperado {esperado_normalizado!r}, obtido {decifrado!r}"
    )


def teste_ida_e_volta_round_trip():
    for frase in ["Ola mundo!", "a", "Teste, 1 2 3.", "SENHA FORTE com Numeros 42"]:
        cifrado = rc4.cifrar(frase, CHAVE_EXEMPLO)
        decifrado = rc4.decifrar(cifrado, CHAVE_EXEMPLO)
        assert decifrado == frase, (
            f"{frase!r} -> {cifrado!r} -> {decifrado!r}"
        )


def teste_texto_vazio_produz_criptograma_vazio():
    assert rc4.cifrar("", CHAVE_EXEMPLO) == ""
    assert rc4.decifrar("", CHAVE_EXEMPLO) == ""


def teste_mesma_chave_e_texto_produzem_sempre_o_mesmo_criptograma():
    # RC4 sem nonce/IV é determinístico -- mesma chave e mesmo texto sempre
    # dão o mesmo criptograma. É justamente essa previsibilidade (reuso de
    # keystream) que motiva o aviso de fraquezas no docstring do módulo.
    a = rc4.cifrar("mensagem repetida", CHAVE_EXEMPLO)
    b = rc4.cifrar("mensagem repetida", CHAVE_EXEMPLO)
    assert a == b, "RC4 determinístico deveria produzir o mesmo criptograma para a mesma entrada"


def teste_chave_errada_nao_recupera_o_texto():
    cifrado = rc4.cifrar("MENSAGEM SECRETA", CHAVE_EXEMPLO)
    resultado = rc4.decifrar(cifrado, "OUTRA CHAVE")
    assert resultado != "MENSAGEM SECRETA", (
        "Decifrar com a chave errada não deveria devolver o texto original"
    )


def teste_decifrar_com_chave_errada_nao_derruba_o_cliente():
    """
    Propriedade de segurança central (mesma regra do playfair.decifrar()):
    client.py chama decifrar() direto na thread de recepção, sem
    try/except. Uma chave errada faz o XOR sair de ASCII quase sempre --
    isso tem que virar texto ilegível, nunca uma exceção.
    """
    cifrado = rc4.cifrar("Ola, tudo bem?", CHAVE_EXEMPLO)
    try:
        resultado = rc4.decifrar(cifrado, "chave totalmente diferente")
    except Exception as e:
        assert False, f"decifrar() com chave errada não deveria lançar exceção: {e}"
    assert isinstance(resultado, str)


def teste_decifrar_texto_que_nao_e_base64_nao_derruba_o_cliente():
    """
    Cobre o cenário em que o remetente escolheu outra cifra (ou nenhuma) e
    o destinatário está configurado para RC4 -- o payload chega como ASCII
    válido (a camada 3 do protocolo já garante isso), mas não é Base64
    bem-formado. decifrar() precisa produzir lixo, não estourar.
    """
    entradas_nao_base64 = [
        "OLA MUNDO",              # texto comum, tamanho não múltiplo de 4
        "DWDTXH DR DPDQKHFHU!",   # criptograma de César, com espaço e pontuação
        "===",                    # só padding
        "!!!",                    # nenhum caractere do alfabeto Base64
    ]
    for entrada in entradas_nao_base64:
        try:
            resultado = rc4.decifrar(entrada, CHAVE_EXEMPLO)
        except Exception as e:
            assert False, f"decifrar({entrada!r}) não deveria lançar exceção: {e}"
        assert isinstance(resultado, str)


def teste_cifrar_com_chave_vazia_estoura_valueerror_claro():
    # Mesma defesa que vigenere._preparar_chave(): cifrar()/decifrar() não
    # podem assumir que o chamador já validou a chave.
    try:
        rc4.cifrar("mensagem", "")
    except ZeroDivisionError:
        assert False, "cifrar() com chave vazia estourou ZeroDivisionError em vez de erro claro"
    except ValueError as e:
        assert "vazia" in str(e).lower(), f"erro pouco claro para chave vazia: {e}"
    else:
        assert False, "cifrar() aceitou chave vazia em silêncio"


TESTES = [
    teste_validar_chave_aceita_chave_valida,
    teste_validar_chave_rejeita_vazia,
    teste_validar_chave_aceita_numeros_e_simbolos_e_espaco,
    teste_validar_chave_rejeita_nao_ascii,
    teste_validar_chave_normaliza_acento,
    teste_validar_chave_aceita_no_limite_de_256,
    teste_validar_chave_rejeita_acima_de_256,
    teste_vetores_canonicos_da_literatura,
    teste_bytes_brutos_bate_com_rc4_xor,
    teste_bytes_brutos_nunca_lanca_excecao_com_lixo,
    teste_vetores_da_disciplina,
    teste_cifrar_produz_base64_valido,
    teste_cifrar_preserva_maiuscula_minuscula_e_pontuacao,
    teste_cifrar_remove_acentos,
    teste_ida_e_volta_round_trip,
    teste_texto_vazio_produz_criptograma_vazio,
    teste_mesma_chave_e_texto_produzem_sempre_o_mesmo_criptograma,
    teste_chave_errada_nao_recupera_o_texto,
    teste_decifrar_com_chave_errada_nao_derruba_o_cliente,
    teste_decifrar_texto_que_nao_e_base64_nao_derruba_o_cliente,
    teste_cifrar_com_chave_vazia_estoura_valueerror_claro,
]


def rodar_todos():
    falhas = 0
    for teste in TESTES:
        try:
            teste()
            print(f"[OK]    {teste.__name__}")
        except AssertionError as e:
            falhas += 1
            print(f"[FALHA] {teste.__name__} -- {e}")

    print(f"\n{len(TESTES) - falhas}/{len(TESTES)} testes passaram.")
    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
