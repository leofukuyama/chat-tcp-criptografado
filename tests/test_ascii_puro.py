"""
Testes da camada de defesa ASCII -- sem envolver rede, socket ou o chat.
Rodar com: python tests/test_ascii_puro.py  (a partir da raiz do projeto)

Este arquivo NUNCA imprime um caractere não-ASCII. As mensagens de falha
identificam os caracteres pelo código (U+XXXX), para que a suíte rode em
qualquer console -- inclusive o cp1252 padrão do Windows.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ascii_puro


# ============================================================
# normalizar()
# ============================================================

def teste_normalizar_remove_acentos():
    assert ascii_puro.normalizar("ÁÉÎÕÜ") == "AEIOU", (
        "Vogais acentuadas deveriam virar as letras base"
    )
    assert ascii_puro.normalizar("Ação") == "Acao", (
        "'Acao' com cedilha e til deveria normalizar para 'Acao'"
    )


def teste_normalizar_trata_cedilha_maiuscula_e_minuscula():
    assert ascii_puro.normalizar("Ç") == "C", "C-cedilha maiusculo -> C"
    assert ascii_puro.normalizar("ç") == "c", "c-cedilha minusculo -> c"


def teste_normalizar_preserva_caixa():
    assert ascii_puro.normalizar("José") == "Jose", (
        "normalizar() nao deve mexer em maiuscula/minuscula -- so em acento. "
        "Vigenere depende disso para preservar a caixa do texto original."
    )


def teste_normalizar_nao_altera_texto_ja_ascii():
    original = "Ola, tudo bem? 42 -- [ok]!"
    assert ascii_puro.normalizar(original) == original, (
        "Texto ja ASCII deve atravessar normalizar() intacto"
    )


def teste_normalizar_nao_inventa_conversao_para_simbolos():
    """Emoji, moedas e alfabetos estrangeiros nao tem 'letra base' ASCII.

    normalizar() deve deixa-los como estao -- quem barra e a validacao.
    Converter para '?' ou remover silenciosamente esconderia do usuario
    que a mensagem dele foi alterada.
    """
    for codigo in ["\U0001F600", "€", "ß", "р"]:
        assert ascii_puro.normalizar(codigo) == codigo, (
            f"U+{ord(codigo):04X} nao deveria ser convertido por normalizar()"
        )


# ============================================================
# eh_ascii()
# ============================================================

def teste_eh_ascii_nos_limites_do_intervalo():
    assert ascii_puro.eh_ascii(chr(0)) is True, "NUL (0) esta dentro do ASCII"
    assert ascii_puro.eh_ascii(chr(127)) is True, "DEL (127) e o ultimo ASCII"
    assert ascii_puro.eh_ascii(chr(128)) is False, "128 e o primeiro fora do ASCII"


def teste_eh_ascii_com_string_vazia():
    assert ascii_puro.eh_ascii("") is True, "String vazia nao tem byte invalido"


def teste_eh_ascii_detecta_um_unico_intruso_no_meio():
    assert ascii_puro.eh_ascii("tudo ok ate aqui € e depois volta") is False, (
        "Um unico caractere fora do ASCII ja invalida a string inteira"
    )


# ============================================================
# caracteres_invalidos()
# ============================================================

def teste_caracteres_invalidos_lista_vazia_quando_tudo_ascii():
    assert ascii_puro.caracteres_invalidos("Ola mundo 123") == []


def teste_caracteres_invalidos_preserva_ordem_de_aparicao():
    texto = "b € a \U0001F600 c"
    assert ascii_puro.caracteres_invalidos(texto) == ["€", "\U0001F600"], (
        "Os ofensores devem sair na ordem em que aparecem no texto"
    )


def teste_caracteres_invalidos_nao_repete():
    texto = "€€€ x €"
    assert ascii_puro.caracteres_invalidos(texto) == ["€"], (
        "O mesmo caractere repetido deve aparecer uma vez so na lista"
    )


# ============================================================
# descrever_invalidos()
# ============================================================

def teste_descrever_invalidos_usa_codigo_unicode():
    descricao = ascii_puro.descrever_invalidos("preco €")
    assert "U+20AC" in descricao, (
        f"A descricao deveria citar o codigo U+20AC, veio: {descricao!r}"
    )


def teste_descrever_invalidos_e_vazia_quando_tudo_ascii():
    assert ascii_puro.descrever_invalidos("tudo ascii") == ""


# ============================================================
# validar()
# ============================================================

def teste_validar_segue_contrato_de_validar_chave():
    """Mesmo formato (bool, str) que os modulos de cifra usam."""
    valido, erro = ascii_puro.validar("mensagem normal")
    assert valido is True, "Texto ASCII deveria ser valido"
    assert erro == "", "Texto valido nao deveria vir com mensagem de erro"

    valido, erro = ascii_puro.validar("mensagem \U0001F600")
    assert valido is False, "Texto com emoji deveria ser invalido"
    assert erro != "", "Texto invalido precisa explicar o motivo"


def teste_validar_nao_normaliza_por_conta_propria():
    """validar() responde sobre o texto que recebeu, sem transforma-lo.

    Quem normaliza antes de validar e preparar(). Se validar() normalizasse
    escondido, um texto acentuado passaria aqui e o chamador acharia que
    podia enviar os bytes originais.
    """
    valido, _ = ascii_puro.validar("Ação")
    assert valido is False, (
        "Texto acentuado ainda nao normalizado nao e ASCII e deve reprovar"
    )


# ============================================================
# preparar()
# ============================================================

def teste_preparar_aceita_acento_e_devolve_ascii():
    resultado = ascii_puro.preparar("Ola, ação do José!")
    assert resultado == "Ola, acao do Jose!", f"Veio: {resultado!r}"
    assert resultado.isascii(), "A saida de preparar() e sempre ASCII"


def teste_preparar_rejeita_o_que_nao_vira_ascii():
    invalidos = {
        "emoji": "Bom dia \U0001F600",
        "moeda": "preco €50",
        "eszett": "Straße",
        "cirilico": "привет",
        "cjk": "日本",
        "grau": "30°",
        "travessao": "a – b",
    }
    for nome, texto in invalidos.items():
        try:
            resultado = ascii_puro.preparar(texto)
        except ascii_puro.ErroAscii:
            continue
        raise AssertionError(
            f"preparar() deveria ter levantado ErroAscii para {nome}, "
            f"mas devolveu {resultado!r}"
        )


def teste_preparar_menciona_o_ofensor_na_excecao():
    try:
        ascii_puro.preparar("preco €")
    except ascii_puro.ErroAscii as erro:
        assert "U+20AC" in str(erro), (
            f"A excecao deveria identificar o caractere, veio: {str(erro)!r}"
        )
        return
    raise AssertionError("preparar() nao levantou ErroAscii")


def teste_preparar_aceita_string_vazia():
    assert ascii_puro.preparar("") == "", "String vazia e ASCII valido"


# ============================================================
# codificar() -- camada 2: impossivel vazar byte alto
# ============================================================

def teste_codificar_devolve_bytes_de_texto_ascii():
    assert ascii_puro.codificar("/sair") == b"/sair"


def teste_codificar_levanta_erro_em_vez_de_gerar_bytes_altos():
    """A camada 2 e a garantia final: nem que a camada 1 falhe, um byte
    >= 0x80 sai do processo. Tem que ser excecao, nunca 'errors=replace'."""
    try:
        resultado = ascii_puro.codificar("oi \U0001F600")
    except ascii_puro.ErroAscii:
        return
    raise AssertionError(
        f"codificar() deveria ter levantado ErroAscii, devolveu {resultado!r}"
    )


def teste_codificar_nao_normaliza_escondido():
    """codificar() e transporte puro. Normalizar aqui mascararia um bug
    da camada 1 -- o texto acentuado tem que ter sido tratado antes."""
    try:
        ascii_puro.codificar("ação")
    except ascii_puro.ErroAscii:
        return
    raise AssertionError(
        "codificar() nao deve normalizar por conta propria; texto acentuado "
        "que chega aqui e sintoma de bug na camada 1 e deve estourar"
    )


# ============================================================
# decodificar() -- camada 3: nada nao-ASCII entra
# ============================================================

def teste_decodificar_aceita_bytes_ascii():
    assert ascii_puro.decodificar(b"SYS:alguem entrou") == "SYS:alguem entrou"


def teste_decodificar_rejeita_qualquer_byte_alto():
    for byte_alto in [0x80, 0xC3, 0xFF]:
        dados = b"inicio ok " + bytes([byte_alto]) + b" fim"
        try:
            resultado = ascii_puro.decodificar(dados)
        except ascii_puro.ErroAscii:
            continue
        raise AssertionError(
            f"decodificar() deveria rejeitar o byte 0x{byte_alto:02X}, "
            f"devolveu {resultado!r}"
        )


def teste_decodificar_rejeita_utf8_valido_mas_nao_ascii():
    """UTF-8 bem formado ainda assim nao passa: o criterio e ASCII, nao
    'decodificavel'. Sem isso, 'acao' acentuado entraria pela rede."""
    try:
        ascii_puro.decodificar("ação".encode("utf-8"))
    except ascii_puro.ErroAscii:
        return
    raise AssertionError("decodificar() aceitou UTF-8 nao-ASCII")


def teste_decodificar_aceita_bytes_vazios():
    assert ascii_puro.decodificar(b"") == "", (
        "recv() vazio sinaliza conexao fechada e e tratado pelo chamador, "
        "nao deve virar excecao de charset aqui"
    )


# ============================================================
# Cobertura do intervalo inteiro
# ============================================================

def teste_ida_e_volta_para_todos_os_128_caracteres_ascii():
    for codigo in range(128):
        caractere = chr(codigo)
        dados = ascii_puro.codificar(caractere)
        assert dados == bytes([codigo]), (
            f"U+{codigo:04X} deveria virar o byte 0x{codigo:02X}"
        )
        assert ascii_puro.decodificar(dados) == caractere, (
            f"Ida e volta falhou para U+{codigo:04X}"
        )


def teste_todo_byte_alto_e_rejeitado_na_decodificacao():
    for codigo in range(128, 256):
        try:
            ascii_puro.decodificar(bytes([codigo]))
        except ascii_puro.ErroAscii:
            continue
        raise AssertionError(f"O byte 0x{codigo:02X} deveria ter sido rejeitado")


# ============================================================
# Contrato transversal: NENHUMA cifra pode produzir saída não-ASCII
# ============================================================
# ascii_puro garante o transporte, mas a garantia só vale de ponta a ponta
# se as cifras também respeitarem o alfabeto. Já houve um caso real: a
# monoalfabética aceitava chave acentuada na validação e a usava crua na
# cifragem, mapeando uma letra para 'Ñ'. Este bloco vigia todas as cifras
# de uma vez, para o mesmo erro não reaparecer em outra.

from cifras.registro import CIFRAS, NOMES

# Uma chave válida por cifra, incluindo variantes acentuadas de propósito.
CHAVES_POR_OPCAO = {
    "1": ["", "ignorada"],
    "2": ["0", "3", "25"],
    "3": ["QWERTYUIOPASDFGHJKLZXCVBNM", "QWERTYUIOPASDFGHJKLZXCVBÑM"],
    "4": ["SEGURANCA", "SEGURANÇA", "chave com espaço"],
    "5": ["CHAVE", "CHÁVE", "cháve"],
}

TEXTOS = [
    "Ataque ao amanhecer",
    "Ola, ação do José!",
    "Encontro as 14:30 -- confirmar!",
    "YAYA COM ESTILO",
    "",
]


def teste_toda_cifra_com_chave_valida_produz_saida_ascii():
    for opcao, chaves in CHAVES_POR_OPCAO.items():
        modulo = CIFRAS[opcao]
        for chave in chaves:
            valido, erro = modulo.validar_chave(chave)
            if not valido:
                continue  # chave recusada nunca chega a cifrar(); tudo bem
            for texto in TEXTOS:
                cifrado = modulo.cifrar(ascii_puro.preparar(texto), chave)
                assert cifrado.isascii(), (
                    f"{NOMES[opcao]} com chave {chave!r} produziu saida "
                    f"nao-ASCII para {texto!r}: "
                    f"{ascii_puro.descrever_invalidos(cifrado)}"
                )


def teste_toda_cifra_com_chave_valida_faz_ida_e_volta():
    """Uma cifra pode ser ASCII e mesmo assim estar corrompendo. Este teste
    fecha essa brecha: o que entra tem de voltar.

    A Playfair fica de fora: ela é lossy POR DEFINIÇÃO, não por defeito --
    funde J em I e insere X de preenchimento entre letras duplicadas e no
    fim de mensagem ímpar. 'Ola, acao do Jose!' volta como
    'OLAX, ACAO DO IOSE!'. Essas perdas já têm testes próprios em
    tests/test_playfair.py (teste_perda_conhecida_j_vira_i e os diag_*), e
    afrouxar a asserção aqui para acomodá-las cegaria o teste para as
    outras quatro cifras. A garantia de ASCII da Playfair continua coberta
    pelo teste acima.
    """
    for opcao, chaves in CHAVES_POR_OPCAO.items():
        if CIFRAS[opcao] is CIFRAS["4"]:
            continue
        modulo = CIFRAS[opcao]
        for chave in chaves:
            valido, _ = modulo.validar_chave(chave)
            if not valido:
                continue
            for texto in TEXTOS:
                preparado = ascii_puro.preparar(texto)
                voltou = modulo.decifrar(modulo.cifrar(preparado, chave), chave)
                assert voltou.upper() == preparado.upper(), (
                    f"{NOMES[opcao]} com chave {chave!r}: "
                    f"{preparado!r} voltou como {voltou!r}"
                )


# ============================================================
# RUNNER
# ============================================================

TESTES = [
    teste_normalizar_remove_acentos,
    teste_normalizar_trata_cedilha_maiuscula_e_minuscula,
    teste_normalizar_preserva_caixa,
    teste_normalizar_nao_altera_texto_ja_ascii,
    teste_normalizar_nao_inventa_conversao_para_simbolos,
    teste_eh_ascii_nos_limites_do_intervalo,
    teste_eh_ascii_com_string_vazia,
    teste_eh_ascii_detecta_um_unico_intruso_no_meio,
    teste_caracteres_invalidos_lista_vazia_quando_tudo_ascii,
    teste_caracteres_invalidos_preserva_ordem_de_aparicao,
    teste_caracteres_invalidos_nao_repete,
    teste_descrever_invalidos_usa_codigo_unicode,
    teste_descrever_invalidos_e_vazia_quando_tudo_ascii,
    teste_validar_segue_contrato_de_validar_chave,
    teste_validar_nao_normaliza_por_conta_propria,
    teste_preparar_aceita_acento_e_devolve_ascii,
    teste_preparar_rejeita_o_que_nao_vira_ascii,
    teste_preparar_menciona_o_ofensor_na_excecao,
    teste_preparar_aceita_string_vazia,
    teste_codificar_devolve_bytes_de_texto_ascii,
    teste_codificar_levanta_erro_em_vez_de_gerar_bytes_altos,
    teste_codificar_nao_normaliza_escondido,
    teste_decodificar_aceita_bytes_ascii,
    teste_decodificar_rejeita_qualquer_byte_alto,
    teste_decodificar_rejeita_utf8_valido_mas_nao_ascii,
    teste_decodificar_aceita_bytes_vazios,
    teste_ida_e_volta_para_todos_os_128_caracteres_ascii,
    teste_todo_byte_alto_e_rejeitado_na_decodificacao,
    teste_toda_cifra_com_chave_valida_produz_saida_ascii,
    teste_toda_cifra_com_chave_valida_faz_ida_e_volta,
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
