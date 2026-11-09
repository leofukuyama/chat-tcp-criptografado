"""
Justificativa dos parâmetros públicos p e g da opção 9 (Diffie-Hellman + César).

O enunciado permite p e g fixos "desde que sejam adequados para
Diffie-Hellman". Como são constantes, a prova é feita uma vez, aqui (e nos
testes), e não toda vez que o chat abre. O roteiro segue a aula:

  1. Por que NÃO usar p = 353 e g = 3 da aula: o ataque de força bruta da
     aula descobre a chave privada na hora.
  2. Por que este p: primo de 2048 bits do RFC 3526 e PRIMO SEGURO
     (p = 2q + 1, q primo), conferido com Miller-Rabin.
  3. Por que g = 11: o teste de raiz primitiva da aula (Passos 1 a 3),
     aplicado a g = 2, 3, ..., 11.
  4. Conclusão.

Todas as contas usam as funções do próprio projeto (cifras/diffie_hellman.py):
exp_mod(), eh_provavel_primo() e eh_raiz_primitiva().

Rodar a partir da raiz do projeto:
    python scripts/verificar_parametros_dh.py            # direto
    python scripts/verificar_parametros_dh.py --pausar   # espera Enter entre as partes
                                                          # (bom para gravar o vídeo)

Sai com código 0 se p e g forem adequados, 1 caso contrário.
"""

import os
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from cifras import diffie_hellman as dh

PAUSAR = "--pausar" in sys.argv
SEGUNDOS_POR_ANO = 365.25 * 24 * 3600
falhas = []


def titulo(texto):
    if PAUSAR:
        input("\n[Enter para continuar]")
    print("\n" + "=" * 78)
    print(texto)
    print("=" * 78)


def conferir(condicao, descricao):
    print(f"  [{'OK' if condicao else 'FALHOU'}] {descricao}")
    if not condicao:
        falhas.append(descricao)


def potencia_de_10(n: int) -> str:
    """Escreve um inteiro enorme como 'aprox. 10^X'."""
    return f"~10^{len(str(n)) - 1}"


def forca_bruta(p, g, publico, limite=None):
    """
    O programa de força bruta da aula: testa CpB = 1, 2, 3, ... calculando
    g^CpB mod p de forma incremental (uma multiplicação por tentativa) até
    bater com o valor público observado.
    Devolve (expoente encontrado ou None, tentativas).
    """
    calculado = 1
    tentativa = 0
    while limite is None or tentativa < limite:
        tentativa += 1
        calculado = (calculado * g) % p
        if calculado == publico:
            return tentativa, tentativa
        if tentativa >= p - 1:
            break
    return None, tentativa


# ============================================================
# 1. POR QUE NÃO OS PARÂMETROS DA AULA
# ============================================================

def parte_1():
    titulo("1. Por que NÃO usar p = 353 e g = 3 (parâmetros da aula)")
    p, g, Yb, Ya = dh.P_AULA, dh.G_AULA, 40, 248
    print(f"  Darth observa na rede: p = {p}, g = {g}, Yb = {Yb}, Ya = {Ya}")
    print("  Força bruta da aula: testar CpB = 1, 2, 3, ... até g^CpB mod p = Yb")

    inicio = time.perf_counter()
    cpb, tentativas = forca_bruta(p, g, Yb)
    decorrido = time.perf_counter() - inicio
    K = dh.exp_mod(Ya, cpb, p)
    print(f"  -> CpB = {cpb} encontrado em {tentativas} tentativas ({decorrido * 1000:.2f} ms)")
    print(f"  -> chave combinada K = Ya^CpB mod p = {Ya}^{cpb} mod {p} = {K}")
    conferir(cpb == 97 and K == 160, "Darth recupera a chave da aula (CpB = 97, K = 160)")
    print(f"  No pior caso são p - 1 = {p - 1} tentativas: p pequeno NÃO é adequado.")

    # Mesmo ataque contra o p do chat, medindo a velocidade desta máquina.
    print("\n  O mesmo ataque contra o p de 2048 bits usado no chat:")
    A_chat = dh.calcular_publico(dh.gerar_privado())
    amostra = 200_000
    inicio = time.perf_counter()
    forca_bruta(dh.P, dh.G, A_chat, limite=amostra)
    por_segundo = amostra / (time.perf_counter() - inicio)
    pior_caso = dh.P - 1
    anos = pior_caso // int(por_segundo * SEGUNDOS_POR_ANO)
    print(f"  -> esta máquina testa ~{por_segundo:,.0f} tentativas por segundo".replace(",", "."))
    print(f"  -> pior caso: p - 1 {potencia_de_10(pior_caso)} tentativas = {potencia_de_10(anos)} anos")
    raiz = 1 << (dh.P.bit_length() // 2)
    print(f"  -> mesmo os algoritmos citados na aula (baby-step giant-step, Pollard rho),")
    print(f"     com custo O(raiz de N), precisariam de {potencia_de_10(raiz)} operações.")
    print("     (Para comparar: a idade do universo é ~10^10 anos.)")


# ============================================================
# 2. POR QUE ESTE p
# ============================================================

def parte_2():
    titulo("2. p: primo de 2048 bits do RFC 3526, grupo 14 (\"2048-bit MODP Group\")")
    print("  Copiado do RFC 3526, seção 3 (hexadecimal, como publicado):")
    for linha in dh.P_HEX_RFC3526_GRUPO14.strip().splitlines():
        print(f"    {linha.strip()}")
    print(f"\n  Em decimal: {dh.resumir(dh.P)}")
    print(f"  Tamanho: {dh.P.bit_length()} bits, {len(str(dh.P))} dígitos decimais")
    conferir(dh.P.bit_length() == 2048, "p tem 2048 bits")

    print("\n  p precisa ser PRIMO (aula: \"p deve ser um inteiro primo\").")
    print("  Com 617 dígitos não dá para testar divisores um a um; usamos Miller-Rabin")
    print("  (40 rodadas: chance de erro menor que 1 em 10^24).")
    print("  Testando p... ", end="", flush=True)
    inicio = time.perf_counter()
    p_primo = dh.eh_provavel_primo(dh.P)
    print(f"{time.perf_counter() - inicio:.1f} s")
    conferir(p_primo, "p é primo")

    print("\n  p também precisa ser um PRIMO SEGURO: p = 2q + 1 com q primo.")
    print("  Motivo: o teste de raiz primitiva da aula exige FATORAR phi(p) = p - 1,")
    print("  e fatorar um número qualquer de 2048 bits é inviável. Com p = 2q + 1,")
    print("  a fatoração é imediata: phi(p) = 2 * q.")
    print(f"  q = (p - 1)/2 = {dh.resumir(dh.Q)}")
    print("  Testando q... ", end="", flush=True)
    inicio = time.perf_counter()
    q_primo = dh.eh_provavel_primo(dh.Q)
    print(f"{time.perf_counter() - inicio:.1f} s")
    conferir(dh.P == 2 * dh.Q + 1, "p = 2q + 1")
    conferir(q_primo, "q é primo  -> p é um primo seguro")


# ============================================================
# 3. POR QUE g = 11
# ============================================================

def parte_3():
    titulo("3. g: raiz primitiva de p (método do slide \"Algoritmo de exponenciação modular\")")
    print("  Aula: g é raiz primitiva de p se, para cada fator primo f de phi(p),")
    print("        g^(phi/f) mod p != 1.")

    print("\n  Relembrando o exemplo da aula (p = 353, phi = 352 = 2^5 * 11):")
    for g in (3, 6):
        r2 = dh.exp_mod(g, 176, 353)
        r11 = dh.exp_mod(g, 32, 353)
        eh = dh.eh_raiz_primitiva(g, 353, dh.FATORES_PHI_AULA)
        print(f"    g = {g}: {g}^176 mod 353 = {r2:>3}   {g}^32 mod 353 = {r11:>3}"
              f"   -> {'É' if eh else 'NÃO é'} raiz primitiva")
    print("    (o slide diz 3^32 mod 353 = 294; o valor correto é 140 -- 294 é 3^11.")
    print("     A conclusão não muda, porque 140 != 1.)")
    conferir(dh.eh_raiz_primitiva(3, 353, dh.FATORES_PHI_AULA)
             and not dh.eh_raiz_primitiva(6, 353, dh.FATORES_PHI_AULA),
             "o método reproduz a aula (3 é, 6 não é raiz primitiva de 353)")

    print("\n  Agora para o p do chat:")
    print("    Passo 1: phi(p) = p - 1")
    print("    Passo 2: phi(p) = 2 * q   (fatores primos: 2 e q)")
    print("    Passo 3: g^(phi/2) mod p = g^q mod p  e  g^(phi/q) mod p = g^2 mod p")
    print()
    print(f"    {'g':>3}  {'g^q mod p':<16} {'g^2 mod p':>9}   resultado")
    menor = None
    for g in range(2, 12):
        rq = dh.exp_mod(g, dh.Q, dh.P)
        r2 = dh.exp_mod(g, 2, dh.P)
        texto_rq = "1" if rq == 1 else ("p - 1" if rq == dh.P - 1 else dh.resumir(rq))
        eh = rq != 1 and r2 != 1
        if eh and menor is None:
            menor = g
        print(f"    {g:>3}  {texto_rq:<16} {r2:>9}   "
              f"{'É raiz primitiva' if eh else 'NÃO é (g^q mod p = 1)'}")

    print("\n  O RFC 3526 usa g = 2, que NÃO é raiz primitiva deste p: ele gera o")
    print("  subgrupo de ordem q, escolha do RFC. A aula define g como raiz primitiva,")
    print(f"  então usamos a menor delas. Um g pequeno é o padrão na prática: todas as")
    print("  raízes primitivas são equivalentes para a segurança, e um g pequeno deixa")
    print("  o cálculo de A e B mais barato.")
    conferir(menor == 11, "a menor raiz primitiva de p é 11")
    conferir(dh.G == menor, f"o chat usa g = {dh.G} (cifras/diffie_hellman.py)")


# ============================================================
# 4. CONCLUSÃO
# ============================================================

def parte_4():
    titulo("4. Conclusão")
    if falhas:
        print("  p e g NÃO foram confirmados. Falhas:")
        for f in falhas:
            print(f"    - {f}")
        return 1
    print(f"  p = primo seguro de 2048 bits (RFC 3526, grupo 14)")
    print(f"  g = {dh.G}, raiz primitiva de p (menor possível)")
    print("  -> parâmetros ADEQUADOS para Diffie-Hellman, como pede o enunciado.")
    print("  Ficam fixos no código; o que muda a cada mensagem são os valores")
    print("  privados a e b, sorteados entre 2 e p - 2.")
    return 0


def main():
    print("Verificação dos parâmetros públicos p e g -- Diffie-Hellman + César (opção 9)")
    parte_1()
    parte_2()
    parte_3()
    sys.exit(parte_4())


if __name__ == "__main__":
    main()
