"""
Testes isolados da Cifra de Playfair -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_playfair.py  (a partir da raiz do projeto)

O arquivo tem duas listas de testes:
  - TESTES: comportamento esperado; falha aqui = regressão.
  - DIAGNOSTICO: casos-limite que HOJE estão quebrados. Servem de
    documentação executável dos defeitos conhecidos; não derrubam o
    código de saída até serem corrigidos.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cifras import playfair

CHAVE_CLASSICA = "PLAYFAIR EXAMPLE"
MATRIZ_CLASSICA = ["PLAYF", "IREXM", "BCDGH", "KNOQS", "TUVWZ"]


# --------------------------------------------------------------------
# validar_chave
# --------------------------------------------------------------------

def teste_validar_chave_aceita_palavra():
    valido, erro = playfair.validar_chave("SEGURANCA")
    assert valido is True, f"Chave válida foi rejeitada: {erro}"


def teste_validar_chave_aceita_expressao_com_espacos():
    valido, erro = playfair.validar_chave(CHAVE_CLASSICA)
    assert valido is True, "Chave com espaço deveria ser aceita (a matriz ignora o espaço)"


def teste_validar_chave_rejeita_vazia_e_sem_letras():
    valido, erro = playfair.validar_chave("")
    assert valido is False, "Chave vazia deveria ser rejeitada"
    assert erro == "A chave deve conter ao menos uma letra."

    valido, erro = playfair.validar_chave("123")
    assert valido is False, "Chave só com números deveria ser rejeitada"

    valido, erro = playfair.validar_chave("!@#")
    assert valido is False, "Chave só com símbolos deveria ser rejeitada"


def teste_validar_chave_aceita_mistura_com_numeros():
    # Comportamento ATUAL: basta existir uma letra; o resto é descartado ao
    # montar a matriz. Difere de vigenere.validar_chave(), que rejeita
    # qualquer caractere não-alfabético -- ver análise (inconsistência de API).
    valido, _ = playfair.validar_chave("chave123")
    assert valido is True, "Chave com letra + número é aceita pelo Playfair"
    assert playfair._montar_matriz("chave123") == playfair._montar_matriz("chave"), (
        "Os caracteres não-alfabéticos deveriam ser simplesmente ignorados na matriz"
    )


# --------------------------------------------------------------------
# Matriz 5x5
# --------------------------------------------------------------------

def teste_matriz_do_exemplo_classico():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    assert matriz == MATRIZ_CLASSICA, f"Esperado {MATRIZ_CLASSICA}, obtido {matriz}"


def teste_matriz_tem_25_letras_unicas_e_sem_j():
    matriz = playfair._montar_matriz("SEGURANCA")
    juntas = "".join(matriz)

    assert len(matriz) == 5 and all(len(linha) == 5 for linha in matriz), (
        f"Matriz deveria ser 5x5, obtido {matriz}"
    )
    assert len(juntas) == 25, f"Matriz deveria ter 25 letras, obtido {len(juntas)}"
    assert len(set(juntas)) == 25, "Matriz não pode ter letras repetidas"
    assert "J" not in juntas, "J não deveria aparecer na matriz (J é fundido em I)"
    assert set(juntas) == set(playfair.ALFABETO), (
        "Matriz deveria conter exatamente o alfabeto de 25 letras"
    )


def teste_matriz_funde_j_da_chave_em_i():
    # "JOGO" -> J vira I; o segundo O é ignorado -> I, O, G
    matriz = playfair._montar_matriz("JOGO")
    assert matriz[0].startswith("IOG"), f"Esperado começar com IOG, obtido {matriz[0]}"


def teste_matriz_ignora_acentos_e_caixa_da_chave():
    assert playfair._montar_matriz("ação") == playfair._montar_matriz("ACAO"), (
        "Chave acentuada/minúscula deveria gerar a mesma matriz que a normalizada"
    )


def teste_localizar_encontra_letra():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    assert playfair._localizar(matriz, "P") == (0, 0)
    assert playfair._localizar(matriz, "H") == (2, 4)
    assert playfair._localizar(matriz, "Z") == (4, 4)


def teste_localizar_falha_para_letra_fora_da_matriz():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    try:
        playfair._localizar(matriz, "J")
    except ValueError:
        return
    assert False, "J não está na matriz; _localizar deveria levantar ValueError"


# --------------------------------------------------------------------
# Montagem de pares
# --------------------------------------------------------------------

def teste_pares_separam_letras_duplicadas_com_x():
    pares = playfair._montar_pares(list("HELLO"))
    esperado = [("H", True, "E", True), ("L", True, "X", False), ("L", True, "O", True)]
    assert pares == esperado, f"Esperado {esperado}, obtido {pares}"


def teste_pares_completam_quantidade_impar_com_x():
    pares = playfair._montar_pares(list("ABC"))
    esperado = [("A", True, "B", True), ("C", True, "X", False)]
    assert pares == esperado, f"Esperado {esperado}, obtido {pares}"


def teste_pares_marcam_x_de_preenchimento_como_nao_real():
    pares = playfair._montar_pares(list("HELLO"))
    reais = [(a_real, b_real) for _, a_real, _, b_real in pares]
    assert reais == [(True, True), (True, False), (True, True)], (
        f"Marcação de letra real/preenchimento incorreta: {reais}"
    )


# --------------------------------------------------------------------
# Regras de transformação do par (linha / coluna / retângulo)
# --------------------------------------------------------------------

def teste_regra_mesma_linha_desloca_para_direita():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)  # linha 0 = PLAYF
    assert playfair._transformar_par(matriz, "P", "L", 1) == ("L", "A")


def teste_regra_mesma_linha_da_a_volta_no_fim():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    # A(0,3) e F(0,4): F está na última coluna e deve voltar para P(0,0)
    assert playfair._transformar_par(matriz, "A", "F", 1) == ("Y", "P")


def teste_regra_mesma_coluna_desloca_para_baixo():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)  # coluna 0 = P I B K T
    assert playfair._transformar_par(matriz, "P", "I", 1) == ("I", "B")


def teste_regra_mesma_coluna_da_a_volta_no_fim():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    # T(4,0) está na última linha da coluna 0 e deve voltar para P(0,0)
    assert playfair._transformar_par(matriz, "P", "T", 1) == ("I", "P")


def teste_regra_do_retangulo_troca_as_colunas():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    assert playfair._transformar_par(matriz, "H", "I", 1) == ("B", "M")


def teste_regra_do_retangulo_e_sua_propria_inversa():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    ida = playfair._transformar_par(matriz, "H", "I", 1)
    volta = playfair._transformar_par(matriz, ida[0], ida[1], -1)
    assert volta == ("H", "I"), f"Retângulo deveria ser sua própria inversa, obtido {volta}"


def teste_passo_negativo_desfaz_linha_e_coluna():
    matriz = playfair._montar_matriz(CHAVE_CLASSICA)
    assert playfair._transformar_par(matriz, "L", "A", -1) == ("P", "L")
    assert playfair._transformar_par(matriz, "I", "B", -1) == ("P", "I")


# --------------------------------------------------------------------
# cifrar / decifrar
# --------------------------------------------------------------------

def teste_cifrar_vetor_canonico():
    # Vetor de referência clássico do Playfair, com a chave padrão da literatura
    resultado = playfair.cifrar("HIDETHEGOLDINTHETREESTUMP", CHAVE_CLASSICA)
    esperado = "BMODZBXDNABEKUDMUIXMMOUVIF"
    assert resultado == esperado, f"Esperado {esperado}, obtido {resultado}"


def teste_decifrar_vetor_canonico():
    # O X inserido entre TRE-E some na limpeza (E X E -> E E), devolvendo
    # exatamente o texto original.
    resultado = playfair.decifrar("BMODZBXDNABEKUDMUIXMMOUVIF", CHAVE_CLASSICA)
    assert resultado == "HIDETHEGOLDINTHETREESTUMP", f"Obtido {resultado}"


def teste_cifrar_exemplo_hello_world():
    resultado = playfair.cifrar("HELLO WORLD", CHAVE_CLASSICA)
    assert resultado == "DMYRAN VQCRGE", f"Esperado 'DMYRAN VQCRGE', obtido {resultado}"


def teste_decifrar_exemplo_hello_world():
    resultado = playfair.decifrar("DMYRAN VQCRGE", CHAVE_CLASSICA)
    assert resultado == "HELLO WORLD", f"Esperado 'HELLO WORLD', obtido {resultado}"


def teste_cifrar_preserva_nao_letras_na_mesma_posicao():
    resultado = playfair.cifrar("OI, 42!", "SEGURANCA")
    assert "".join(c for c in resultado if not c.isalpha()) == ", 42!", (
        f"Caracteres não-alfabéticos foram alterados: {resultado}"
    )


def teste_cifrar_normaliza_caixa_e_acentos():
    assert playfair.cifrar("ola mundo", "SEGURANCA") == playfair.cifrar("OLA MUNDO", "SEGURANCA"), (
        "Minúsculas deveriam ser normalizadas antes de cifrar"
    )
    assert playfair.cifrar("Ação", "SEGURANCA") == playfair.cifrar("ACAO", "SEGURANCA"), (
        "Acento e cedilha deveriam ser normalizados antes de cifrar"
    )


def teste_cifrar_nao_altera_texto_sem_letras():
    assert playfair.cifrar("123 !?", "SEGURANCA") == "123 !?"


def teste_texto_de_uma_letra_recebe_padding_e_volta_limpo():
    cifrado = playfair.cifrar("A", "SEGURANCA")
    assert len(cifrado) == 2, f"Letra sozinha deveria virar um par completo, obtido {cifrado}"
    assert playfair.decifrar(cifrado, "SEGURANCA") == "A", "Padding final deveria ser removido"


def teste_letras_duplicadas_coladas_sobrevivem_ao_round_trip():
    for texto in ["PASSE", "SUCESSO", "AA", "COMMITTEE"]:
        cifrado = playfair.cifrar(texto, "SEGURANCA")
        decifrado = playfair.decifrar(cifrado, "SEGURANCA")
        assert decifrado == texto, f"{texto} -> {cifrado} -> {decifrado}"


def teste_round_trip_de_frases():
    frases = ["OLA MUNDO", "ATACAR AO AMANHECER", "REUNIAO AS 15H!", "TESTE, 1 2 3."]
    for frase in frases:
        cifrado = playfair.cifrar(frase, "SEGURANCA")
        decifrado = playfair.decifrar(cifrado, "SEGURANCA")
        assert decifrado == playfair._normalizar(frase), (
            f"{frase!r} -> {cifrado!r} -> {decifrado!r}"
        )


def teste_perda_conhecida_j_vira_i():
    # Limitação INERENTE ao Playfair de 25 letras, não é bug: J e I dividem
    # a mesma célula da matriz, então o J original não volta.
    cifrado = playfair.cifrar("LARANJA", "SEGURANCA")
    assert playfair.decifrar(cifrado, "SEGURANCA") == "LARANIA"


def teste_chave_errada_nao_recupera_o_texto():
    cifrado = playfair.cifrar("MENSAGEM SECRETA", "SEGURANCA")
    assert playfair.decifrar(cifrado, "OUTRACHAVE") != "MENSAGEM SECRETA", (
        "Decifrar com a chave errada não deveria devolver o texto original"
    )


def teste_chaves_equivalentes_geram_a_mesma_cifra():
    # Letras repetidas na chave são ignoradas na montagem da matriz, então
    # "SEGURANCA" e "SEGURANCASEGURANCA" cifram igual.
    assert playfair.cifrar("MENSAGEM", "SEGURANCA") == playfair.cifrar(
        "MENSAGEM", "SEGURANCASEGURANCA"
    ), "Chave com letras repetidas deveria gerar a mesma matriz"


# --------------------------------------------------------------------
# DIAGNÓSTICO -- defeitos confirmados (falham hoje)
# --------------------------------------------------------------------

def diag_x_entre_duplicadas_separadas_por_espaco():
    """A heurística de remoção do X olha o caractere vizinho, não a LETRA
    vizinha: com um espaço no meio ("L L"), o X de preenchimento não é
    reconhecido e sobra no texto decifrado."""
    cifrado = playfair.cifrar("L L", "SEGURANCA")
    decifrado = playfair.decifrar(cifrado, "SEGURANCA")
    assert decifrado == "L L", f"'L L' -> {cifrado!r} -> {decifrado!r}"


def diag_letra_x_duplicada():
    """O Playfair clássico usa um filler alternativo (Q/Z) quando a própria
    letra duplicada é X. Aqui "XX" vira o par (X, X), que as regras de
    linha/coluna não separam, e a limpeza acaba comendo as duas letras."""
    cifrado = playfair.cifrar("XX", "SEGURANCA")
    decifrado = playfair.decifrar(cifrado, "SEGURANCA")
    assert decifrado == "XX", f"'XX' -> {cifrado!r} -> {decifrado!r}"


def diag_decifrar_com_numero_impar_de_letras():
    """decifrar() ignora a última letra quando a contagem é ímpar
    (range(0, n-1, 2)), mas depois consome um item do iterador para CADA
    letra do texto -> StopIteration não tratada. Uma mensagem truncada no
    recv() derrubaria o laço de recepção do chat."""
    try:
        playfair.decifrar("ABC", "SEGURANCA")
    except StopIteration:
        assert False, "decifrar() estourou StopIteration com número ímpar de letras"


def diag_decifrar_com_letras_minusculas():
    """decifrar() não normaliza a entrada, então qualquer texto que não
    tenha vindo do próprio cifrar() (minúsculas, acento) explode em
    ValueError dentro de _localizar()."""
    try:
        playfair.decifrar("dmyran vqcrge", CHAVE_CLASSICA)
    except ValueError as e:
        assert False, f"decifrar() estourou ValueError com entrada minúscula: {e}"


def diag_caractere_alfabetico_fora_de_az():
    """isalpha() é verdadeiro para caracteres que não existem na matriz.
    'ŉ'.upper() == 'ʼN' e o modificador 'ʼ' passa no isalpha(), chega em
    _localizar() e levanta ValueError."""
    try:
        playfair.cifrar("ŉ", "SEGURANCA")
    except ValueError as e:
        assert False, f"cifrar() estourou ValueError com letra fora de A-Z: {e}"


TESTES = [
    teste_validar_chave_aceita_palavra,
    teste_validar_chave_aceita_expressao_com_espacos,
    teste_validar_chave_rejeita_vazia_e_sem_letras,
    teste_validar_chave_aceita_mistura_com_numeros,
    teste_matriz_do_exemplo_classico,
    teste_matriz_tem_25_letras_unicas_e_sem_j,
    teste_matriz_funde_j_da_chave_em_i,
    teste_matriz_ignora_acentos_e_caixa_da_chave,
    teste_localizar_encontra_letra,
    teste_localizar_falha_para_letra_fora_da_matriz,
    teste_pares_separam_letras_duplicadas_com_x,
    teste_pares_completam_quantidade_impar_com_x,
    teste_pares_marcam_x_de_preenchimento_como_nao_real,
    teste_regra_mesma_linha_desloca_para_direita,
    teste_regra_mesma_linha_da_a_volta_no_fim,
    teste_regra_mesma_coluna_desloca_para_baixo,
    teste_regra_mesma_coluna_da_a_volta_no_fim,
    teste_regra_do_retangulo_troca_as_colunas,
    teste_regra_do_retangulo_e_sua_propria_inversa,
    teste_passo_negativo_desfaz_linha_e_coluna,
    teste_cifrar_vetor_canonico,
    teste_decifrar_vetor_canonico,
    teste_cifrar_exemplo_hello_world,
    teste_decifrar_exemplo_hello_world,
    teste_cifrar_preserva_nao_letras_na_mesma_posicao,
    teste_cifrar_normaliza_caixa_e_acentos,
    teste_cifrar_nao_altera_texto_sem_letras,
    teste_texto_de_uma_letra_recebe_padding_e_volta_limpo,
    teste_letras_duplicadas_coladas_sobrevivem_ao_round_trip,
    teste_round_trip_de_frases,
    teste_perda_conhecida_j_vira_i,
    teste_chave_errada_nao_recupera_o_texto,
    teste_chaves_equivalentes_geram_a_mesma_cifra,
]

DIAGNOSTICO = [
    diag_x_entre_duplicadas_separadas_por_espaco,
    diag_letra_x_duplicada,
    diag_decifrar_com_numero_impar_de_letras,
    diag_decifrar_com_letras_minusculas,
    diag_caractere_alfabetico_fora_de_az,
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

    print("\n--- diagnóstico de casos-limite (defeitos conhecidos) ---")
    bugs = 0
    for teste in DIAGNOSTICO:
        try:
            teste()
            print(f"[OK]    {teste.__name__} (defeito parece corrigido)")
        except AssertionError as e:
            bugs += 1
            print(f"[BUG]   {teste.__name__} -- {e}")
    print(f"{bugs}/{len(DIAGNOSTICO)} defeitos ainda presentes.")

    if falhas > 0:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
