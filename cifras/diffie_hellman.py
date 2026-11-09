"""
Diffie-Hellman -- negociação de chave, implementado do zero.

Diffie-Hellman NÃO é uma cifra: ele não esconde a mensagem, só permite que
dois participantes cheguem ao MESMO número secreto trocando apenas valores
públicos por um canal inseguro. Neste projeto o segredo vira o deslocamento
da cifra de César (cifras/cesar.py), que é quem de fato cifra o texto.

NOMENCLATURA. O código segue o enunciado do projeto (a, b, A, B, s, k). A
correspondência com os slides da aula é:

    Projeto                 Aula (Bob / Alicie)
    ---------------------   ------------------------------
    p, g                    p, g        (públicos)
    a  (remetente)          CpB         (privado)
    b  (destinatário)       CpA         (privado)
    A = g^a mod p           Yb = g^CpB mod p
    B = g^b mod p           Ya = g^CpA mod p
    s = B^a mod p           K  = Ya^CpB mod p
    s = A^b mod p           K  = Yb^CpA mod p
    k = 1 + (s mod 25)      (passo extra do projeto: vira a chave de César)

ESCOLHA DE p E g. A aula usa p = 353 e g = 3, ótimos para fazer a conta no
quadro e péssimos na prática: com p tão pequeno, o Darth descobre a chave
privada por força bruta em no máximo 352 tentativas (é exatamente o
programa de força bruta mostrado na aula). O enunciado pede parâmetros
"adequados para Diffie-Hellman", então usamos:

  p = primo de 2048 bits do RFC 3526, grupo 14 ("2048-bit MODP Group"),
      padronizado e usado em IKE/IPsec, SSH e TLS. Tem 617 dígitos.

  p é um PRIMO SEGURO: p = 2q + 1 com q também primo. Isso é o que torna
  possível aplicar o teste de raiz primitiva da aula a um número deste
  tamanho, porque o teste exige fatorar phi(p) = p - 1, e fatorar um número
  de 2048 bits qualquer é inviável. Para um primo seguro a fatoração é
  imediata: phi(p) = 2 * q.

  g = 11, a MENOR raiz primitiva de p. Atenção: o RFC usa g = 2, mas 2 NÃO
  é raiz primitiva deste p (2^q mod p = 1; o mesmo vale para 3, 4, ..., 10).
  O RFC escolhe 2 de propósito, porque ele gera o subgrupo de ordem q. A
  aula define g como raiz primitiva, então seguimos a aula. O teste é o
  mesmo do slide "Algoritmo de exponenciação modular":

      Passo 1: phi(p) = p - 1
      Passo 2: fatorar phi(p) = 2 * q
      Passo 3: g^(phi/2) mod p != 1  e  g^(phi/q) mod p != 1
               => g é raiz primitiva

  Como p e g são constantes, isso é provado uma vez, não a cada execução:
  pelos testes (tests/test_diffie_hellman.py) e pelo script
  scripts/verificar_parametros_dh.py, que mostra o passo a passo.

Os cálculos usam somente exp_mod() deste módulo. Não se usa a função
embutida pow do Python nem biblioteca de criptografia; a única coisa da
biblioteca padrão é o sorteio dos valores privados (módulo `secrets`, gerador criptográfico do
sistema operacional).
"""

import secrets

# ============================================================
# PARÂMETROS PÚBLICOS
# ============================================================

# Copiado do RFC 3526, seção 3, exatamente como publicado (blocos de 32 bits
# em hexadecimal). Manter o formato original facilita conferir dígito a
# dígito com a fonte.
P_HEX_RFC3526_GRUPO14 = """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""

P = int("".join(P_HEX_RFC3526_GRUPO14.split()), 16)
Q = (P - 1) // 2          # p = 2q + 1
G = 11                    # menor raiz primitiva de P (ver docstring)

# Fatores primos de phi(P) = P - 1 = 2 * Q. É a entrada do Passo 3 do teste
# de raiz primitiva.
FATORES_PHI = (2, Q)

# Parâmetros didáticos da aula. Ficam aqui SÓ para os testes reproduzirem
# os números dos slides (Yb = 40, Ya = 248, K = 160). Nunca são usados no chat.
P_AULA = 353
G_AULA = 3
FATORES_PHI_AULA = (2, 11)   # 352 = 2^5 * 11

# Quantidade de deslocamentos da cifra de César que o projeto permite: 1..25.
# O 0 fica de fora porque deslocar 0 deixaria o texto igual ao original.
DESLOCAMENTOS = 25

# Sinaliza para client.py que esta opção não tem chave digitada pelo
# usuário: a chave é negociada pela rede a cada mensagem.
NEGOCIA_CHAVE_POR_MENSAGEM = True


# ============================================================
# EXPONENCIAÇÃO MODULAR
# ============================================================

def exp_mod(base: int, expoente: int, modulo: int) -> int:
    """
    Calcula (base ^ expoente) mod modulo -- a função expMod() da aula.

    Na aula, com p = 353, dava até para multiplicar a base expoente vezes
    seguidas. Com um expoente de 2048 bits isso levaria mais tempo que a
    idade do universo, então usamos "elevar ao quadrado e multiplicar"
    (square-and-multiply): percorremos os bits do expoente, elevando a base
    ao quadrado a cada bit e multiplicando no resultado quando o bit é 1.
    Reduzimos mod `modulo` a cada passo para os números não crescerem.
    São cerca de 2 * 2048 multiplicações em vez de 2^2048.

    Exemplo (3^5): 5 = 101 em binário
        bit 1 -> resultado = 1 * 3 = 3       base = 3^2 = 9
        bit 0 -> resultado = 3               base = 9^2 = 81
        bit 1 -> resultado = 3 * 81 = 243

    >>> exp_mod(3, 5, 1000)
    243
    >>> exp_mod(3, 97, 353)      # Yb da aula
    40
    >>> exp_mod(3, 233, 353)     # Ya da aula
    248
    """
    if modulo <= 0:
        raise ValueError("o módulo precisa ser positivo")
    if expoente < 0:
        raise ValueError("o expoente não pode ser negativo")
    if modulo == 1:
        return 0

    resultado = 1
    base = base % modulo
    while expoente > 0:
        if expoente & 1:                      # bit atual vale 1
            resultado = (resultado * base) % modulo
        base = (base * base) % modulo         # próxima potência de 2
        expoente >>= 1                        # passa para o próximo bit
    return resultado


# ============================================================
# VERIFICAÇÃO DOS PARÂMETROS
# ============================================================

def eh_provavel_primo(n: int, rodadas: int = 40) -> bool:
    """
    Teste de primalidade de Miller-Rabin, usando exp_mod().

    Para números pequenos dá para testar divisores um a um; para 617
    dígitos, não. Miller-Rabin diz "composto" com certeza ou "primo" com
    probabilidade de erro menor que 4^(-rodadas) (com 40 rodadas, menos de
    1 em 10^24).

    >>> eh_provavel_primo(353)
    True
    >>> eh_provavel_primo(352)
    False
    """
    if n < 2:
        return False
    for pequeno in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % pequeno == 0:
            return n == pequeno

    # Escreve n - 1 = d * 2^r com d ímpar.
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rodadas):
        testemunha = 2 + secrets.randbelow(n - 3)
        x = exp_mod(testemunha, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = exp_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def eh_raiz_primitiva(g: int, p: int, fatores_phi) -> bool:
    """
    Teste de raiz primitiva da aula (slides "Algoritmo de exponenciação
    modular"): g é raiz primitiva de p se, para todo fator primo f de
    phi(p) = p - 1, g^(phi/f) mod p != 1.

    >>> eh_raiz_primitiva(3, 353, (2, 11))     # exemplo da aula
    True
    >>> eh_raiz_primitiva(6, 353, (2, 11))     # exercício da aula: 6^32 = 1
    False
    """
    if not 1 < g < p:
        return False
    phi = p - 1
    return all(exp_mod(g, phi // f, p) != 1 for f in fatores_phi)


# ============================================================
# OPERAÇÕES DE CADA NEGOCIAÇÃO
# ============================================================

def gerar_privado(p: int = P) -> int:
    """
    Sorteia um valor privado novo, com 2 <= x <= p - 2 (mesmo intervalo da
    aula: "tal que 2 <= CpB <= p - 2").

    Usa `secrets`, o gerador criptográfico do sistema operacional. O módulo
    `random` não serve: ele é previsível a partir de algumas saídas
    observadas, o que entregaria o valor privado.
    """
    return 2 + secrets.randbelow(p - 3)


def calcular_publico(privado: int, p: int = P, g: int = G) -> int:
    """A = g^a mod p  (ou B = g^b mod p).  Na aula: Yb = g^CpB mod p."""
    return exp_mod(g, privado, p)


def validar_publico(valor: int, p: int = P) -> None:
    """
    Recusa valores públicos degenerados vindos da rede.

    Um participante adulterado (ou o Darth, como man-in-the-middle ativo)
    poderia mandar A = 1: aí s = 1^b mod p = 1 para qualquer b, e a chave
    ficaria conhecida sem ninguém perceber. O mesmo acontece com 0 e com
    p - 1 (que só gera 1 ou p - 1). Um valor legítimo g^x com 2 <= x <= p-2
    nunca cai nesses casos.
    """
    if not 2 <= valor <= p - 2:
        raise ValueError(f"valor público fora do intervalo [2, p-2]: {resumir(valor)}")


def calcular_segredo(publico_do_outro: int, privado: int, p: int = P) -> int:
    """
    s = B^a mod p (remetente) ou s = A^b mod p (destinatário).
    Na aula: K = Ya^CpB mod p = Yb^CpA mod p.

    >>> calcular_segredo(248, 97, 353)    # Bob na aula
    160
    >>> calcular_segredo(40, 233, 353)    # Alicie na aula
    160
    """
    return exp_mod(publico_do_outro, privado, p)


def chave_cesar(segredo: int) -> int:
    """
    k = 1 + (s mod 25): transforma o segredo em um deslocamento de 1 a 25.

    >>> chave_cesar(160)    # segredo da aula
    11
    """
    return 1 + (segredo % DESLOCAMENTOS)


# ============================================================
# EXIBIÇÃO
# ============================================================

def resumir(n: int, pontas: int = 12) -> str:
    """
    Números de 617 dígitos não cabem numa linha de terminal. Mostra o
    começo, o fim e o tamanho, o suficiente para comparar visualmente o
    mesmo valor em dois terminais.

    >>> resumir(160)
    '160'
    >>> resumir(10 ** 40)
    '100000000000...000000000000 (41 dígitos)'
    """
    texto = str(n)
    if len(texto) <= 2 * pontas + 3:
        return texto
    return f"{texto[:pontas]}...{texto[-pontas:]} ({len(texto)} dígitos)"
