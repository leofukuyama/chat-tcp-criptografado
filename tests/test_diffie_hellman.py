"""
Testes do Diffie-Hellman (cifras/diffie_hellman.py) e da sessão por
mensagem (sessao_dh.py) -- sem rede: duas sessões ligadas por uma fila.

Rodar com: python tests/test_diffie_hellman.py  (a partir da raiz)
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import protocolo
import sessao_dh
from cifras import cesar
from cifras import diffie_hellman as dh


# ============================================================
# NÚMEROS DA AULA (p = 353, g = 3, CpB = 97, CpA = 233)
# ============================================================

def teste_exp_mod_reproduz_os_numeros_da_aula():
    assert dh.exp_mod(3, 97, 353) == 40, "Yb = 3^97 mod 353 deveria ser 40"
    assert dh.exp_mod(3, 233, 353) == 248, "Ya = 3^233 mod 353 deveria ser 248"
    assert dh.exp_mod(248, 97, 353) == 160, "K de Bob = 248^97 mod 353 deveria ser 160"
    assert dh.exp_mod(40, 233, 353) == 160, "K de Alicie = 40^233 mod 353 deveria ser 160"


def teste_exp_mod_reproduz_o_man_in_the_middle_da_aula():
    assert dh.exp_mod(3, 13, 353) == 175, "Yd1 = 3^13 mod 353"
    assert dh.exp_mod(3, 7, 353) == 69, "Yd2 = 3^7 mod 353"
    assert dh.exp_mod(175, 97, 353) == 204, "k de Bob com Darth"
    assert dh.exp_mod(69, 233, 353) == 125, "k de Alicie com Darth"
    assert dh.exp_mod(40, 13, 353) == 204 and dh.exp_mod(248, 7, 353) == 125


def teste_raiz_primitiva_exemplos_da_aula():
    assert dh.exp_mod(3, 176, 353) == 352
    # O slide diz 3^32 mod 353 = 294, mas o valor correto é 140 (294 é
    # 3^11 mod 353). A conclusão do slide não muda: 140 != 1.
    assert dh.exp_mod(3, 32, 353) == 140
    assert dh.eh_raiz_primitiva(3, 353, dh.FATORES_PHI_AULA), "3 é raiz primitiva de 353"
    assert dh.exp_mod(6, 32, 353) == 1
    assert not dh.eh_raiz_primitiva(6, 353, dh.FATORES_PHI_AULA), "6 não é raiz primitiva de 353"


def teste_raiz_primitiva_confere_com_a_definicao_por_enumeracao():
    # Definição da aula: q é raiz primitiva se q^1..q^(p-1) mod p gera
    # todos os números de 1 a p-1 sem repetir. Para p = 353 dá para
    # enumerar e comparar com o teste rápido (passos 1-3).
    for g in range(2, 353):
        gerados = {dh.exp_mod(g, i, 353) for i in range(1, 353)}
        pela_definicao = len(gerados) == 352
        assert dh.eh_raiz_primitiva(g, 353, (2, 11)) == pela_definicao, f"g = {g}"


def teste_chave_da_aula_vira_deslocamento_11():
    assert dh.chave_cesar(160) == 11, "k = 1 + (160 mod 25) = 11"


def teste_negociacao_completa_com_numeros_da_aula():
    p, g, a, b = dh.P_AULA, dh.G_AULA, 97, 233
    A = dh.calcular_publico(a, p, g)
    B = dh.calcular_publico(b, p, g)
    assert (A, B) == (40, 248)
    s_rem = dh.calcular_segredo(B, a, p)
    s_dest = dh.calcular_segredo(A, b, p)
    assert s_rem == s_dest == 160
    k = dh.chave_cesar(s_rem)
    assert cesar.decifrar(cesar.cifrar("ATACAR BASE NORTE.", str(k)), str(k)) == "ATACAR BASE NORTE."


# ============================================================
# EXPONENCIAÇÃO MODULAR
# ============================================================

def teste_exp_mod_casos_limite():
    assert dh.exp_mod(5, 0, 7) == 1
    assert dh.exp_mod(0, 5, 7) == 0
    assert dh.exp_mod(5, 3, 1) == 0
    assert dh.exp_mod(-2, 3, 7) == (-8) % 7


def teste_exp_mod_confere_com_numeros_de_2048_bits():
    # pow() aparece SÓ aqui, como gabarito independente. O código do chat
    # não usa pow().
    rng = random.Random(2026)
    for _ in range(5):
        base = rng.randrange(2, dh.P)
        expoente = rng.randrange(2, dh.P)
        assert dh.exp_mod(base, expoente, dh.P) == pow(base, expoente, dh.P)


def teste_codigo_do_chat_nao_usa_pow_nem_biblioteca_de_troca_de_chaves():
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for arquivo in ("cifras/diffie_hellman.py", "sessao_dh.py", "client.py", "server.py"):
        codigo = open(os.path.join(raiz, arquivo), encoding="utf-8").read()
        assert "pow(" not in codigo, f"{arquivo} usa pow()"
        for proibido in ("cryptography", "Crypto.", "ssl", "hashlib", "hmac"):
            assert f"import {proibido}" not in codigo and f"from {proibido}" not in codigo, (
                f"{arquivo} importa {proibido}"
            )


# ============================================================
# PARÂMETROS DO CHAT
# ============================================================

def teste_p_e_o_primo_de_2048_bits_do_rfc_3526():
    assert dh.P.bit_length() == 2048
    assert len(str(dh.P)) == 617
    texto_hex = format(dh.P, "X")
    assert texto_hex.startswith("FFFFFFFFFFFFFFFFC90FDAA22168C234")
    assert texto_hex.endswith("15728E5A8AACAA68FFFFFFFFFFFFFFFF")


def teste_p_e_um_primo_seguro():
    assert dh.eh_provavel_primo(dh.P), "p deveria ser primo"
    assert dh.eh_provavel_primo(dh.Q), "q = (p-1)/2 deveria ser primo"
    assert dh.P == 2 * dh.Q + 1


def teste_miller_rabin_reconhece_primos_e_compostos():
    primos = [2, 3, 5, 353, 7919, 2 ** 61 - 1]
    compostos = [1, 4, 352, 561, 7917, 2 ** 61 + 1, 353 * 7919]  # 561 = Carmichael
    assert all(dh.eh_provavel_primo(n) for n in primos)
    assert not any(dh.eh_provavel_primo(n) for n in compostos)


def teste_g_11_e_a_menor_raiz_primitiva_de_p():
    assert dh.G == 11
    assert dh.eh_raiz_primitiva(11, dh.P, dh.FATORES_PHI)
    for g in range(2, 11):
        assert not dh.eh_raiz_primitiva(g, dh.P, dh.FATORES_PHI), f"{g} não deveria ser raiz primitiva"


def teste_script_de_verificacao_confirma_p_e_g():
    # scripts/verificar_parametros_dh.py é a justificativa de p e g mostrada
    # no vídeo; precisa terminar com sucesso e concluir "ADEQUADOS".
    import subprocess
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    resultado = subprocess.run(
        [sys.executable, os.path.join("scripts", "verificar_parametros_dh.py")],
        cwd=raiz, capture_output=True, text=True, encoding="utf-8",
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
    )
    assert resultado.returncode == 0, resultado.stdout + resultado.stderr
    assert "ADEQUADOS" in resultado.stdout and "FALHOU" not in resultado.stdout


def teste_chave_cesar_fica_sempre_entre_1_e_25():
    assert {dh.chave_cesar(s) for s in range(0, 1000)} == set(range(1, 26))


def teste_valor_privado_fica_entre_2_e_p_menos_2():
    valores = {dh.gerar_privado(7) for _ in range(500)}
    assert valores == {2, 3, 4, 5}, f"para p = 7 os privados válidos são 2..5, saiu {valores}"
    grande = dh.gerar_privado()
    assert 2 <= grande <= dh.P - 2


def teste_valores_publicos_degenerados_sao_recusados():
    for ruim in (0, 1, dh.P - 1, dh.P, -5):
        try:
            dh.validar_publico(ruim)
        except ValueError:
            continue
        raise AssertionError(f"valor público {ruim} deveria ser recusado")
    dh.validar_publico(dh.calcular_publico(dh.gerar_privado()))


# ============================================================
# SESSÃO: DOIS CLIENTES LIGADOS DIRETAMENTE
# ============================================================

class Par:
    """Duas sessões (alice e bob) e a "rede" entre elas, que registra tudo."""

    def __init__(self, p=dh.P, g=dh.G):
        self.rede = []            # (destino, tipo, payload) ainda não entregues
        self.trafego = []         # tudo que passou pela rede, para auditoria
        self.telas = {"alice": [], "bob": []}
        self.alice = sessao_dh.SessaoDH(self._para("bob"), self.telas["alice"].append, p, g)
        self.bob = sessao_dh.SessaoDH(self._para("alice"), self.telas["bob"].append, p, g)
        self.recebidas = {"alice": [], "bob": []}
        # O que o servidor faz quando o segundo participante entra.
        self.alice.definir_participantes(2)
        self.bob.definir_participantes(2)

    def _para(self, destino):
        def enviar(tipo, payload):
            self.rede.append((destino, tipo, payload))
            self.trafego.append((tipo, payload))
        return enviar

    def entregar(self):
        while self.rede:
            destino, tipo, payload = self.rede.pop(0)
            sessao = getattr(self, destino)
            if tipo == protocolo.TIPO_NEGOCIACAO:
                sessao.receber_negociacao(payload)
            else:
                self.recebidas[destino].append(sessao.receber_mensagem(payload))


def teste_cinco_mensagens_consecutivas_cada_uma_com_nova_negociacao():
    par = Par()
    textos = ["OLA BOB", "OLA BOB", "ATACAR BASE NORTE.", "AS 10H", "CONFIRMA?"]
    for t in textos:
        par.alice.enviar_texto(t)
        par.entregar()

    assert par.recebidas["bob"] == textos, "Bob deveria recuperar todos os textos originais"
    assert par.alice.chaves_aceitas == par.bob.chaves_aceitas, "mesma chave nos dois clientes"
    ks = par.alice.chaves_aceitas
    assert len(ks) == 5 and all(1 <= k <= 25 for k in ks)
    assert all(ks[i] != ks[i + 1] for i in range(4)), f"chaves consecutivas iguais: {ks}"

    negociacoes_A = [p for t, p in par.trafego if t == protocolo.TIPO_NEGOCIACAO and p.startswith("A ")]
    assert len(negociacoes_A) >= 5, "cada mensagem precisa de uma negociação própria"
    ids = [p.split(" ")[1] for p in negociacoes_A]
    valores_A = [p.split(" ")[3] for p in negociacoes_A]
    assert len(set(ids)) == len(ids) and len(set(valores_A)) == len(valores_A), (
        "cada negociação deve ter id e valor público novos (valor privado renovado)"
    )


def teste_mesmo_texto_repetido_gera_negociacao_nova():
    par = Par()
    for _ in range(3):
        par.alice.enviar_texto("IGUAL")
        par.entregar()
    cifrados = [p for t, p in par.trafego if t == protocolo.TIPO_MENSAGEM]
    assert len(cifrados) == 3
    assert cifrados[0] != cifrados[1] and cifrados[1] != cifrados[2], (
        "com chaves diferentes, o mesmo texto deveria gerar criptogramas diferentes"
    )


def teste_conversa_nos_dois_sentidos_compartilha_a_regra_da_mensagem_anterior():
    par = Par()
    for i in range(8):
        (par.alice if i % 2 == 0 else par.bob).enviar_texto(f"MSG {i}")
        par.entregar()
    ks = par.alice.chaves_aceitas
    assert ks == par.bob.chaves_aceitas
    assert all(ks[i] != ks[i + 1] for i in range(len(ks) - 1))
    assert par.recebidas["bob"] == ["MSG 0", "MSG 2", "MSG 4", "MSG 6"]
    assert par.recebidas["alice"] == ["MSG 1", "MSG 3", "MSG 5", "MSG 7"]


def teste_chave_igual_a_anterior_forca_nova_negociacao():
    # Força a 2ª negociação a sortear os MESMOS valores privados da 1ª, o
    # que dá o mesmo k. A 3ª sorteia valores diferentes.
    sorteios = iter([97, 233, 97, 233, 5, 7, 11, 13, 17, 19])
    original = dh.gerar_privado
    dh.gerar_privado = lambda p=dh.P: next(sorteios)
    try:
        par = Par(p=dh.P_AULA, g=dh.G_AULA)
        par.alice.enviar_texto("PRIMEIRA")
        par.entregar()
        par.alice.enviar_texto("SEGUNDA")
        par.entregar()
    finally:
        dh.gerar_privado = original

    assert par.alice.chaves_aceitas[0] == 11, "a=97, b=233 -> k = 11 (números da aula)"
    assert par.alice.chaves_aceitas == par.bob.chaves_aceitas
    assert par.alice.chaves_aceitas[1] != 11, "a chave repetida deveria ter sido descartada"
    assert par.recebidas["bob"] == ["PRIMEIRA", "SEGUNDA"]

    tentativas = [p.split(" ")[2] for t, p in par.trafego if t == protocolo.TIPO_NEGOCIACAO and p.startswith("A ")]
    assert tentativas == ["1", "1", "2"], f"a 2ª mensagem deveria precisar de 2 tentativas: {tentativas}"
    for lado in ("alice", "bob"):
        assert any("IGUAL ao da mensagem anterior" in l for l in par.telas[lado]), (
            f"{lado} deveria mostrar que detectou a chave repetida"
        )


def teste_segredos_nunca_trafegam():
    capturados = {}
    original_privado, original_segredo = dh.gerar_privado, dh.calcular_segredo

    def privado(p=dh.P):
        x = original_privado(p)
        capturados.setdefault("privados", []).append(x)
        return x

    def segredo(publico, priv, p=dh.P):
        s = original_segredo(publico, priv, p)
        capturados.setdefault("segredos", []).append(s)
        return s

    dh.gerar_privado, dh.calcular_segredo = privado, segredo
    try:
        par = Par()
        for t in ("UM", "DOIS", "TRES"):
            par.alice.enviar_texto(t)
            par.entregar()
    finally:
        dh.gerar_privado, dh.calcular_segredo = original_privado, original_segredo

    tudo = " ".join(p for _, p in par.trafego)
    for valor in capturados["privados"] + capturados["segredos"]:
        assert str(valor) not in tudo, "valor privado ou segredo apareceu na rede"
    for tipo, payload in par.trafego:
        if tipo == protocolo.TIPO_NEGOCIACAO:
            assert payload.split(" ")[0] in ("A", "B"), f"quadro D inesperado: {payload[:20]}"
        else:
            assert payload not in ("UM", "DOIS", "TRES"), "texto claro na rede"


def teste_colisao_os_dois_enviam_ao_mesmo_tempo():
    par = Par()
    par.alice.enviar_texto("DA ALICE")
    par.bob.enviar_texto("DO BOB")
    par.entregar()
    assert par.recebidas["bob"] == ["DA ALICE"]
    assert par.recebidas["alice"] == ["DO BOB"]
    ks = par.alice.chaves_aceitas
    assert ks == par.bob.chaves_aceitas and len(ks) == 2 and ks[0] != ks[1]


def teste_varias_mensagens_digitadas_rapido_entram_na_fila():
    par = Par()
    for t in ("A1", "A2", "A3"):
        par.alice.enviar_texto(t)
    par.entregar()
    assert par.recebidas["bob"] == ["A1", "A2", "A3"]
    assert par.alice.chaves_aceitas == par.bob.chaves_aceitas


def teste_texto_cifrado_sem_negociacao_e_descartado():
    par = Par()
    assert par.bob.receber_mensagem("KHOOR") is None
    assert any("SEM negociação" in l for l in par.telas["bob"])


def teste_valor_publico_degenerado_vindo_da_rede_e_recusado():
    par = Par()
    par.bob.receber_negociacao("A deadbeefdeadbeef 1 1")    # A = 1 -> s = 1 sempre
    assert par.rede == [], "não deveria responder a um A degenerado"
    assert any("recusada" in l for l in par.telas["bob"])
    par.bob.receber_negociacao("lixo")
    assert any("malformado" in l for l in par.telas["bob"])


# ============================================================
# PARTICIPANTES: SOZINHO, SAÍDA NO MEIO, NOVA CONVERSA
# ============================================================

def teste_sozinho_a_mensagem_e_recusada_com_aviso():
    rede, tela = [], []
    sessao = sessao_dh.SessaoDH(lambda t, s: rede.append((t, s)), tela.append)
    sessao.enviar_texto("TEM ALGUEM?")           # nenhum aviso do servidor ainda
    sessao.definir_participantes(1)
    sessao.enviar_texto("TEM ALGUEM?")
    assert rede == [], "sozinho, nada pode ir para a rede (o A se perderia)"
    assert sum("não há ninguém na sala" in l for l in tela) == 2
    assert any("Aguardando o outro participante" in l for l in tela)


def teste_outro_sai_no_meio_da_negociacao_e_a_sessao_nao_trava():
    par = Par()
    par.alice.enviar_texto("PRIMEIRA")
    par.alice.enviar_texto("NA FILA")
    # O A chega ao Bob, mas ele sai antes de responder: o B nunca vem.
    destino, tipo, payload = par.rede.pop(0)
    assert tipo == protocolo.TIPO_NEGOCIACAO and payload.startswith("A ")
    par.alice.definir_participantes(1)

    assert any("negociação em andamento cancelada" in l for l in par.telas["alice"])
    assert any("2 mensagem(ns) NÃO enviada(s)" in l for l in par.telas["alice"])

    # Entra outra pessoa: a Alice precisa conseguir conversar normalmente.
    par.rede.clear()
    par.bob = sessao_dh.SessaoDH(par._para("alice"), par.telas["bob"].append)
    par.bob.definir_participantes(2)
    par.alice.definir_participantes(2)
    par.alice.enviar_texto("DEPOIS")
    par.entregar()
    assert par.recebidas["bob"] == ["DEPOIS"], "a sessão da Alice ficou travada"


def teste_nova_conversa_nao_herda_a_chave_anterior_nem_a_numeracao():
    par = Par()
    for t in ("UM", "DOIS"):
        par.alice.enviar_texto(t)
        par.entregar()
    assert par.alice.ultimo_k is not None and par.alice.mensagens_entregues == 2

    for sessao in (par.alice, par.bob):
        sessao.definir_participantes(1)
        sessao.definir_participantes(2)
    assert par.alice.ultimo_k is None and par.bob.ultimo_k is None, (
        "o passo 6 vale entre ESTES dois clientes: a conversa nova começa sem k anterior"
    )
    par.alice.enviar_texto("TRES")
    par.entregar()
    assert par.recebidas["bob"][-1] == "TRES"
    assert any("MENSAGEM #1 " in l for l in par.telas["alice"][-12:]), "a numeração recomeça"
    assert any("primeira mensagem" in l for l in par.telas["bob"][-12:])


# ============================================================
# RUNNER
# ============================================================

TESTES = [v for k, v in list(globals().items()) if k.startswith("teste_") and callable(v)]


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
    if falhas:
        sys.exit(1)


if __name__ == "__main__":
    rodar_todos()
