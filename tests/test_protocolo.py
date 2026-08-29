"""
Testes do enquadramento de mensagens -- sem envolver rede ou socket.
Rodar com: python tests/test_protocolo.py  (a partir da raiz do projeto)

Este arquivo NUNCA imprime um caractere não-ASCII: mensagens de falha
identificam bytes por código, para rodar em console cp1252.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ascii_puro
import protocolo


# ============================================================
# empacotar()
# ============================================================

def teste_empacotar_monta_cabecalho_e_payload():
    assert protocolo.empacotar(protocolo.TIPO_MENSAGEM, "HELLO") == b"M0005HELLO"


def teste_empacotar_conta_o_tamanho_do_payload_nao_do_quadro():
    quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "OLA MUNDO")
    assert quadro == b"M0009OLA MUNDO", f"veio {quadro!r}"
    assert len(quadro) == protocolo.TAMANHO_CABECALHO + 9


def teste_empacotar_aceita_payload_vazio():
    assert protocolo.empacotar(protocolo.TIPO_CONTROLE, "") == b"C0000"


def teste_empacotar_rejeita_tipo_desconhecido():
    try:
        protocolo.empacotar("X", "oi")
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("tipo desconhecido deveria ter sido rejeitado")


def teste_empacotar_rejeita_payload_nao_ascii():
    """O enquadramento nao afrouxa a garantia de ASCII: ele a reaproveita."""
    try:
        protocolo.empacotar(protocolo.TIPO_MENSAGEM, "cafe \U0001F600")
    except ascii_puro.ErroAscii:
        return
    raise AssertionError("payload nao-ASCII deveria ter sido rejeitado")


def teste_empacotar_rejeita_payload_longo_demais():
    """O campo de tamanho tem 4 digitos, entao 10000 nao cabe. Precisa dar
    erro claro em vez de gerar um cabecalho truncado e corromper o fluxo."""
    try:
        protocolo.empacotar(protocolo.TIPO_MENSAGEM, "A" * (protocolo.PAYLOAD_MAXIMO + 1))
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("payload acima do maximo deveria ter sido rejeitado")


def teste_empacotar_aceita_exatamente_o_payload_maximo():
    quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "A" * protocolo.PAYLOAD_MAXIMO)
    assert quadro.startswith(b"M9999"), f"cabecalho inesperado: {quadro[:8]!r}"


def teste_quadro_inteiro_e_ascii():
    """O cabecalho tambem trafega, entao ele proprio precisa ser ASCII --
    e por isso o tamanho vai em digitos decimais, e nao em bytes binarios."""
    quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "ATAQUE AO AMANHECER")
    assert all(b < 128 for b in quadro), f"cabecalho vazou byte alto: {quadro!r}"


# ============================================================
# Desempacotador -- o defeito que motivou tudo isto
# ============================================================

def teste_desempacota_um_quadro_completo():
    d = protocolo.Desempacotador()
    quadros = d.alimentar(b"M0005HELLO")
    assert len(quadros) == 1, f"esperava 1 quadro, veio {len(quadros)}"
    assert quadros[0].texto == "HELLO"
    assert quadros[0].tipo == protocolo.TIPO_MENSAGEM


def teste_dois_quadros_grudados_saem_separados():
    """ESTE e o defeito original: duas mensagens enviadas em sequencia
    rapida chegavam coladas em um unico recv() e eram decifradas como se
    fossem uma so, gerando lixo (e derrubando o cliente na Playfair)."""
    d = protocolo.Desempacotador()
    grudado = b"M0009OLA MUNDOC0005/sair"
    quadros = d.alimentar(grudado)

    assert [q.texto for q in quadros] == ["OLA MUNDO", "/sair"], (
        f"os dois quadros deveriam sair separados, veio {[q.texto for q in quadros]}"
    )
    assert [q.tipo for q in quadros] == [protocolo.TIPO_MENSAGEM, protocolo.TIPO_CONTROLE]


def teste_tres_quadros_grudados_saem_separados():
    d = protocolo.Desempacotador()
    grudado = b"".join([
        protocolo.empacotar(protocolo.TIPO_MENSAGEM, "UM"),
        protocolo.empacotar(protocolo.TIPO_SISTEMA, "DOIS"),
        protocolo.empacotar(protocolo.TIPO_CONTROLE, "TRES"),
    ])
    assert [q.texto for q in d.alimentar(grudado)] == ["UM", "DOIS", "TRES"]


def teste_quadro_partido_e_remontado():
    """A outra metade do mesmo defeito: mensagem maior que o recv() chegava
    picada e cada pedaco era tratado como uma mensagem inteira."""
    d = protocolo.Desempacotador()
    assert d.alimentar(b"M0009OLA") == [], "quadro incompleto nao deve produzir nada"
    quadros = d.alimentar(b" MUNDO")
    assert [q.texto for q in quadros] == ["OLA MUNDO"], f"veio {[q.texto for q in quadros]}"


def teste_quadro_remontado_byte_a_byte():
    """Pior caso possivel de fragmentacao."""
    d = protocolo.Desempacotador()
    quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "ATAQUE AO AMANHECER")

    coletados = []
    for i in range(len(quadro)):
        coletados.extend(d.alimentar(quadro[i:i + 1]))

    assert [q.texto for q in coletados] == ["ATAQUE AO AMANHECER"], (
        f"veio {[q.texto for q in coletados]}"
    )


def teste_cabecalho_incompleto_nao_produz_nada():
    d = protocolo.Desempacotador()
    assert d.alimentar(b"M00") == [], "cabecalho de 3 bytes ainda esta incompleto"
    # completa o cabecalho ("M0004") e manda 3 dos 4 bytes do payload
    assert d.alimentar(b"04abc") == [], "faltava 1 byte do payload"
    assert [q.texto for q in d.alimentar(b"d")] == ["abcd"]


def teste_alimentar_vazio_nao_produz_nada():
    d = protocolo.Desempacotador()
    assert d.alimentar(b"") == []


def teste_payload_vazio_e_um_quadro_valido():
    d = protocolo.Desempacotador()
    assert [q.texto for q in d.alimentar(b"C0000")] == [""]


def teste_payload_no_tamanho_maximo():
    d = protocolo.Desempacotador()
    grande = "A" * protocolo.PAYLOAD_MAXIMO
    quadros = d.alimentar(protocolo.empacotar(protocolo.TIPO_MENSAGEM, grande))
    assert [q.texto for q in quadros] == [grande]


def teste_desempacotadores_tem_estado_independente():
    """Cada conexao precisa do seu: o buffer de um cliente nao pode
    contaminar o de outro."""
    a, b = protocolo.Desempacotador(), protocolo.Desempacotador()
    a.alimentar(b"M0005HEL")
    assert b.alimentar(b"") == [], "o buffer de 'a' vazou para 'b'"
    assert [q.texto for q in a.alimentar(b"LO")] == ["HELLO"]


# ============================================================
# Payload invalido: descarta O QUADRO, sem perder a sincronia
# ============================================================

def teste_payload_nao_ascii_vira_quadro_marcado_com_erro():
    d = protocolo.Desempacotador()
    payload = "ação".encode("utf-8")
    bruto = b"M" + f"{len(payload):04d}".encode("ascii") + payload

    quadros = d.alimentar(bruto)

    assert len(quadros) == 1, f"esperava 1 quadro, veio {len(quadros)}"
    assert quadros[0].texto is None, "quadro invalido nao deve expor texto"
    assert quadros[0].erro != "", "quadro invalido precisa dizer o motivo"


def teste_quadro_invalido_nao_quebra_a_sincronia():
    """Vantagem real do tamanho no cabecalho: sabemos exatamente onde o
    quadro ruim termina, entao da para pular so ele. Com delimitador nao
    daria -- um payload corrompido levaria o resto do fluxo junto."""
    payload = "ção".encode("utf-8")
    ruim = b"M" + f"{len(payload):04d}".encode("ascii") + payload
    bom = protocolo.empacotar(protocolo.TIPO_MENSAGEM, "DEPOIS")

    d = protocolo.Desempacotador()
    quadros = d.alimentar(ruim + bom)

    assert len(quadros) == 2, f"esperava 2 quadros, veio {len(quadros)}"
    assert quadros[0].texto is None, "o primeiro era invalido"
    assert quadros[1].texto == "DEPOIS", (
        f"o quadro seguinte deveria ter sido lido normalmente, veio {quadros[1].texto!r}"
    )


def teste_quadro_invalido_carrega_os_bytes_completos():
    """O servidor precisa dos bytes crus para decidir o que repassar, e
    nunca decodifica o payload -- ele nao tem a chave."""
    d = protocolo.Desempacotador()
    quadros = d.alimentar(b"M0005HELLO")
    assert quadros[0].bytes_completos == b"M0005HELLO"


# ============================================================
# Cabecalho corrompido: nao da para ressincronizar
# ============================================================

def teste_tamanho_nao_numerico_e_erro_fatal():
    """Sem um tamanho valido nao ha como saber onde o quadro termina, entao
    nao ha como pular o quadro ruim -- o fluxo esta perdido e a unica saida
    honesta e derrubar a conexao."""
    d = protocolo.Desempacotador()
    try:
        d.alimentar(b"MABCDpayload")
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("tamanho nao numerico deveria ser erro fatal")


def teste_tipo_desconhecido_e_erro_fatal():
    d = protocolo.Desempacotador()
    try:
        d.alimentar(b"Z0005HELLO")
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("tipo desconhecido deveria ser erro fatal")


def teste_cabecalho_com_byte_nao_ascii_e_erro_fatal():
    d = protocolo.Desempacotador()
    try:
        d.alimentar(bytes([0xFF]) + b"0005HELLO")
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("cabecalho com byte alto deveria ser erro fatal")


def teste_cliente_falando_protocolo_antigo_e_detectado():
    """Um client.py desatualizado mandaria texto cru, sem cabecalho. Melhor
    falhar alto e claro do que interpretar isso como um quadro qualquer."""
    d = protocolo.Desempacotador()
    try:
        d.alimentar(b"ATAQUE AO AMANHECER")
    except protocolo.ErroProtocolo:
        return
    raise AssertionError("texto sem cabecalho deveria ser detectado")


# ============================================================
# Ida e volta
# ============================================================

def teste_ida_e_volta_preserva_tipo_e_texto():
    casos = [
        (protocolo.TIPO_MENSAGEM, "ROD, DFDR GR MRVH!"),
        (protocolo.TIPO_SISTEMA, "Alguem entrou no chat :D"),
        (protocolo.TIPO_CONTROLE, "/sair"),
        (protocolo.TIPO_MENSAGEM, ""),
        (protocolo.TIPO_MENSAGEM, "   "),
    ]
    for tipo, texto in casos:
        d = protocolo.Desempacotador()
        quadros = d.alimentar(protocolo.empacotar(tipo, texto))
        assert len(quadros) == 1, f"{texto!r}: esperava 1 quadro"
        assert quadros[0].tipo == tipo, f"{texto!r}: tipo trocado"
        assert quadros[0].texto == texto, f"{texto!r}: veio {quadros[0].texto!r}"


def teste_ida_e_volta_com_todos_os_128_caracteres_ascii():
    """Inclui os de controle: com tamanho no cabecalho, nenhum caractere
    precisa de escape -- nem o \\n, que quebraria um protocolo por
    delimitador de linha."""
    texto = "".join(chr(c) for c in range(128))
    d = protocolo.Desempacotador()
    quadros = d.alimentar(protocolo.empacotar(protocolo.TIPO_MENSAGEM, texto))
    assert [q.texto for q in quadros] == [texto]


# ============================================================
# RUNNER
# ============================================================

TESTES = [
    teste_empacotar_monta_cabecalho_e_payload,
    teste_empacotar_conta_o_tamanho_do_payload_nao_do_quadro,
    teste_empacotar_aceita_payload_vazio,
    teste_empacotar_rejeita_tipo_desconhecido,
    teste_empacotar_rejeita_payload_nao_ascii,
    teste_empacotar_rejeita_payload_longo_demais,
    teste_empacotar_aceita_exatamente_o_payload_maximo,
    teste_quadro_inteiro_e_ascii,
    teste_desempacota_um_quadro_completo,
    teste_dois_quadros_grudados_saem_separados,
    teste_tres_quadros_grudados_saem_separados,
    teste_quadro_partido_e_remontado,
    teste_quadro_remontado_byte_a_byte,
    teste_cabecalho_incompleto_nao_produz_nada,
    teste_alimentar_vazio_nao_produz_nada,
    teste_payload_vazio_e_um_quadro_valido,
    teste_payload_no_tamanho_maximo,
    teste_desempacotadores_tem_estado_independente,
    teste_payload_nao_ascii_vira_quadro_marcado_com_erro,
    teste_quadro_invalido_nao_quebra_a_sincronia,
    teste_quadro_invalido_carrega_os_bytes_completos,
    teste_tamanho_nao_numerico_e_erro_fatal,
    teste_tipo_desconhecido_e_erro_fatal,
    teste_cabecalho_com_byte_nao_ascii_e_erro_fatal,
    teste_cliente_falando_protocolo_antigo_e_detectado,
    teste_ida_e_volta_preserva_tipo_e_texto,
    teste_ida_e_volta_com_todos_os_128_caracteres_ascii,
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
