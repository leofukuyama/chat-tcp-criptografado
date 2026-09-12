# DES (Data Encryption Standard) — Guia de Estudo

> Baseado nos slides da Aula 4 (UniSENAI-PR). Cobre o raciocínio completo: por que
> cifras de bloco simples não funcionam na prática, como a cifra de Feistel resolve
> o problema, e como o DES implementa essa estrutura passo a passo, com um exemplo
> numérico completo.

## Índice

1. [Cifra de bloco](#1-cifra-de-bloco)
2. [O problema do tamanho do bloco](#2-o-problema-do-tamanho-do-bloco)
3. [Cifra de Feistel](#3-cifra-de-feistel)
4. [DES — visão geral](#4-des--visão-geral)
5. [DES — geração das subchaves](#5-des--geração-das-subchaves)
6. [DES — estrutura de uma rodada](#6-des--estrutura-de-uma-rodada)
7. [Exemplo prático completo](#7-exemplo-prático-completo)
8. [Descriptografia no DES](#8-descriptografia-no-des)
9. [DES e 3DES](#9-des-e-3des)
10. [Resumo / pontos-chave](#10-resumo--pontos-chave)

---

## 1. Cifra de bloco

Uma **cifra de bloco** opera sobre um bloco de texto plano de **n bits** e produz
um texto cifrado também de **n bits**.

- Existem `2^n` blocos de texto claro possíveis.
- Exemplo com `n = 4`: existem `2^4 = 16` blocos possíveis (`0000`, `0001`, `0010`, ... `1111`).

Do ponto de vista estrutural, a cifra de bloco é uma **substituição geral**: cada
bloco de entrada é mapeado para um bloco de saída de mesmo tamanho, através de uma
tabela (ou circuito) que faz o papel de "decodificador → embaralhador → codificador".

### Reversibilidade

Para que a cifra seja utilizável (ou seja, para que seja possível decifrar), o
mapeamento **precisa ser reversível** — uma bijeção: cada texto claro leva a um
único texto cifrado, e vice-versa.

Exemplo para `n = 2`:

| Texto claro | Texto cifrado (mapeamento **reversível**) | Texto cifrado (mapeamento **irreversível**) |
|---|---|---|
| 00 | 11 | 11 |
| 01 | 10 | 10 |
| 10 | 00 | 01 |
| 11 | 01 | 01 |

No mapeamento irreversível, `10` e `11` produzem o mesmo cifrado (`01`), então não
há como saber, ao decifrar `01`, qual dos dois era o texto original. Uma cifra útil
não pode ter essa ambiguidade.

---

## 2. O problema do tamanho do bloco

Suponha `n = 4` bits usado em um sistema real:

- **Bloco pequeno → vulnerável a análise estatística.** Se um atacante captura o
  texto cifrado `0100`, ele sabe que o texto claro é uma das `2^4 = 16`
  possibilidades — um espaço de busca pequeno.
- **Blocos pequenos se aproximam de uma cifra monoalfabética** (fácil de atacar via
  frequência de símbolos).
- **Blocos grandes aumentam exponencialmente o tamanho da chave necessária** para
  descrever o mapeamento completo.

### Por que blocos grandes exigem chaves absurdamente grandes

Se a cifra é implementada como uma tabela de substituição completa (um mapeamento
arbitrário de todo bloco de entrada para todo bloco de saída), a **chave** precisa
descrever essa tabela inteira:

```
tamanho da chave = n × 2^n bits
```

- Para `n = 4`: `4 × 2^4 = 4 × 16 = 64 bits` de chave — para cifrar blocos de
  apenas 4 bits!
- Para `n = 64` (tamanho de bloco real, como no DES):

```
64 × 2^64 = 64 × 18.446.744.073.709.551.616
          = 1.180.591.620.717.411.303.424 bits
          ≈ 147.574.000 Terabytes de chave
```

Isso é completamente inviável. Para blocos de 128 bits (como no AES) seria ainda
pior. **Conclusão:** não dá para implementar a cifra de bloco "ideal" (substituição
totalmente arbitrária) na prática — é preciso uma **aproximação** que seja segura o
suficiente, mas viável de implementar. É exatamente isso que a **cifra de Feistel**
resolve.

---

## 3. Cifra de Feistel

- Criada pela **IBM em 1973**.
- É a base estrutural de várias cifras simétricas de bloco: **DES, 3DES, RC5**, entre
  outras.
- **Entrada:**
  - Bloco de texto plano de 64 bits, dividido em duas metades: `L0` (esquerda) e
    `R0` (direita), cada uma com 32 bits.
  - Uma chave `K`.
  - O processamento ocorre em **n rodadas** (no DES, 16 rodadas).

### Ideia central: cifra de produto

A cifra de Feistel usa o conceito de **cifra de produto**: executar duas ou mais
cifras simples em sequência, de modo que o resultado seja mais forte que qualquer
uma das cifras componentes isoladamente.

```
C1(simples) * C2(simples) * C3(simples) = Cp (mais robusta)
```

Essa ideia é inspirada nas **máquinas de rotores** (como a Enigma): cada rotor
sozinho é apenas uma cifra monoalfabética fraca, mas o **conjunto** de rotores
girando em conjunto multiplica as possibilidades e torna a cifra muito mais forte.

### Confusão e difusão

A cifra de Feistel combina dois mecanismos complementares (conceitos de Shannon):

| Mecanismo | Objetivo | Como o DES implementa |
|---|---|---|
| **Substituição (Confusão)** | Tornar a relação estatística entre texto cifrado e chave o mais complexa possível | **S-BOX** (substitution box) |
| **Permutação (Difusão)** | Espalhar a influência de cada bit do texto plano, evitando padrões previsíveis | **P-BOX** (permutation box) |

### Estrutura de uma rodada de Feistel

Em cada rodada `i`, a partir de `(LEi-1, REi-1)` e da subchave `Ki`:

```
LEi = REi-1
REi = LEi-1  XOR  F(REi-1, Ki)
```

Ou seja: a metade direita da rodada anterior "passa direto" para virar a metade
esquerda da rodada atual, enquanto a nova metade direita é o resultado do XOR entre
a antiga metade esquerda e a saída da função `F` (que mistura a metade direita
anterior com a subchave da rodada).

Esse processo se repete por todas as rodadas (16, no caso do DES), e ao final é
aplicada uma troca de metades seguida de uma permutação final.

---

## 4. DES — visão geral

- **DES = Data Encryption Standard**.
- Adotado pelo **governo americano em 1977**.
- Desenvolvido e **patenteado pela IBM**.
- **Controverso:** havia suspeita de que o governo americano tivesse instalado uma
  *backdoor*, já que as tabelas **P-BOX e S-BOX eram mantidas em segredo** no
  projeto original.
- Foi usado até **1999**, quando foi substituído pelo **3DES**.
- **Hoje é considerado inseguro**, pois sua chave de **64 bits efetivos (56 bits úteis)
  é pequena demais** para os padrões atuais de poder computacional.
- Curiosidade histórica: já em **1977**, Diffie e Hellman projetaram (no papel) uma
  máquina capaz de quebrar o DES por força bruta, mas o poder computacional da
  época ainda não permitia construí-la.

### Entrada e saída

- **Texto claro:** bloco de 64 bits.
- **Chave:** 64 bits (dos quais apenas 56 são efetivamente usados — os outros 8 são
  bits de paridade, descartados na primeira etapa).
- Usa uma **rede de Feistel** com uma série de substituições (S-BOX) e permutações
  (P-BOX), transformando 64 bits de entrada em 64 bits de texto cifrado.
- **As mesmas etapas/estrutura são usadas tanto para cifrar quanto para decifrar** —
  só muda a ordem em que as subchaves são aplicadas (ver seção 8).

O DES tem exatamente a estrutura de uma cifra de Feistel, **exceto** pelas duas
permutações extras que acontecem antes da primeira rodada e depois da última:

- **IP** — Permutação Inicial (Initial Permutation), aplicada ao texto claro.
- **IP⁻¹** — Permutação Inicial Inversa, aplicada ao final, depois da troca de
  metades da última rodada.

Fluxograma geral:

```
Texto claro (64 bits)              Chave (64 bits)
        │                                │
        ▼                                ▼
  Permutação Inicial (IP)         Escolha Permutada 1 (PC-1) → 56 bits
        │                                │
        ▼                                ▼
    Rodada 1  ◄──── K1 ──── Deslocamento circular à esquerda → PC-2 (48 bits)
        │                                │
        ▼                                ▼
    Rodada 2  ◄──── K2 ──── Deslocamento circular à esquerda → PC-2 (48 bits)
        │                                │
       ...                              ...
        │                                │
        ▼                                ▼
    Rodada 16 ◄──── K16 ─── Deslocamento circular à esquerda → PC-2 (48 bits)
        │
        ▼
  Troca de 32 bits (LE16 ↔ RE16)
        │
        ▼
  Permutação Inicial Inversa (IP⁻¹)
        │
        ▼
  Texto cifrado (64 bits)
```

Faltam esclarecer dois pontos: **como as subchaves são geradas** e **como a função
F funciona internamente**. É o que as próximas seções cobrem.

---

## 5. DES — geração das subchaves

### Por que precisamos de subchaves

- O DES tem **16 rodadas**.
- Cada rodada precisa de **sua própria subchave**: a partir da chave original `K`
  (64 bits), são derivadas `K1, K2, K3, ..., K16` (48 bits cada).
- Reutilizar a mesma chave em todas as rodadas enfraqueceria drasticamente a cifra
  (menos difusão entre rodadas).

### Passo a passo do algoritmo de geração de subchaves

**1. Permutação PC-1 (Permuted Choice 1): 64 → 56 bits**

A chave original tem 64 bits, mas 8 deles são bits de paridade e são descartados.
A tabela `PC-1` seleciona e reordena os 56 bits restantes:

```
PC-1
57 49 41 33 25 17  9  1
58 50 42 34 26 18 10  2
59 51 43 35 27 19 11  3
60 52 44 36 63 55 47 39
31 23 15  7 62 54 46 38
30 22 14  6 61 53 45 37
29 21 13  5 28 20 12  4
```

Cada número indica a **posição do bit original** que vai para aquela posição na
saída. Por exemplo, `k[57] = 1` significa "o primeiro bit da chave permutada é o
bit 57 da chave original".

**2. Divisão em duas metades de 28 bits: `C0` e `D0`**

O resultado de 56 bits (`kp`) é dividido ao meio:

```
kp = C0 (28 bits) + D0 (28 bits)
```

**3. Deslocamento circular à esquerda (por rodada)**

Para cada rodada `n` (1 a 16), `Cn-1` e `Dn-1` sofrem um deslocamento circular à
esquerda (*left shift*), gerando `Cn` e `Dn`. O número de posições deslocadas segue
uma tabela fixa:

| Rodada | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Deslocamentos | 1 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 1 |

Note que a maioria das rodadas desloca 2 bits, mas as rodadas 1, 2, 9 e 16 deslocam
apenas 1 bit.

**4. Concatenação e permutação PC-2 (Permuted Choice 2): 56 → 48 bits**

Em cada rodada, `Cn` e `Dn` são concatenados (`CDn`, 56 bits) e então uma segunda
tabela de permutação, `PC-2`, seleciona **48 dos 56 bits** e os reordena, produzindo
a subchave `Kn` daquela rodada:

```
PC-2
14 17 11 24  1  5  3 28
15  6 21 10 23 19 12  4
26  8 16  7 27 20 13  2
41 52 31 37 47 55 30 40
51 45 33 48 44 49 39 56
34 53 46 42 50 36 29 32
```

Esse processo é repetido para as 16 rodadas, produzindo as 16 subchaves
`K1, K2, ..., K16`, cada uma com 48 bits.

### Exemplo numérico (dos slides)

Considere a chave `K` de 64 bits:

```
k = 00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001
```

Após aplicar `PC-1`, obtemos `kp` (56 bits):

```
kp = 1111000 0110011 0010101 0101111 0101010 1011001 1001111 0001111
```

Dividindo ao meio:

```
c0 = 1111000 0110011 0010101 0101111
d0 = 0101010 1011001 1001111 0001111
```

Rodada 1 (deslocamento de 1 bit à esquerda):

```
c1 = 1110000 1100110 0101010 1011111
d1 = 1010101 0110011 0011110 0011110
```

Concatenando `c1` e `d1` e aplicando `PC-2`, obtemos a primeira subchave:

```
cd1 = 1110000 1100110 0101010 1011111 1010101 0110011 0011110 0011110

k1  = 000110 110000 001011 101111 111111 000111 000001 110010   (48 bits)
```

Repetindo o processo (rodada 2, deslocamento de 1 bit adicional):

```
c2 = 1100001 1001100 1010101 0111111
d2 = 0101010 1100110 0111100 0111101

k2 = 011110 011010 111011 011001 110110 111100 100111 100101
```

O mesmo procedimento é aplicado até `k16`, produzindo as 16 subchaves usadas em
cada rodada do algoritmo.

---

## 6. DES — estrutura de uma rodada

Cada rodada recebe `LEi-1` e `REi-1` (32 bits cada) e a subchave `Ki` (48 bits), e
produz:

```
LEi = REi-1
REi = LEi-1  XOR  F(REi-1, Ki)
```

O "coração" de cada rodada é a **função F**, que transforma `REi-1` (32 bits) usando
`Ki` (48 bits) em uma saída de 32 bits. A função F tem 4 etapas internas:

### 6.1. Permutação inicial (antes da primeira rodada)

Antes de tudo, o texto claro (64 bits) passa por uma **permutação inicial (IP)**,
seguindo uma tabela fixa que reorganiza os bits — sem alterar a quantidade, só a
ordem:

```
IP
58 50 42 34 26 18 10  2
60 52 44 36 28 20 12  4
62 54 46 38 30 22 14  6
64 56 48 40 32 24 16  8
57 49 41 33 25 17  9  1
59 51 43 35 27 19 11  3
61 53 45 37 29 21 13  5
63 55 47 39 31 23 15  7
```

Depois da IP, o bloco resultante (64 bits) é dividido em `LE0` (32 bits) e `RE0`
(32 bits).

### 6.2. Expansão de bits (E-BOX): 32 → 48 bits

Como a subchave tem 48 bits e `REi-1` tem apenas 32, é preciso **expandir** `REi-1`
para 48 bits antes do XOR. Isso é feito com a tabela de expansão `E`, que **repete
alguns bits** (cada bit de borda de um grupo de 4 aparece em dois grupos
adjacentes):

```
E (bit-selection table)
32  1  2  3  4  5
 4  5  6  7  8  9
 8  9 10 11 12 13
12 13 14 15 16 17
16 17 18 19 20 21
20 21 22 23 24 25
24 25 26 27 28 29
28 29 30 31 32  1
```

### 6.3. XOR com a subchave

```
saída_expandida (48 bits)  XOR  Ki (48 bits)  =  resultado (48 bits)
```

### 6.4. Substituição via S-BOX: 48 → 32 bits

O resultado do XOR (48 bits) é dividido em **8 grupos de 6 bits**, um para cada
uma das 8 S-BOXes (`S1` a `S8`). Cada S-BOX transforma seus 6 bits de entrada em
**4 bits de saída**, reduzindo o total de volta para `8 × 4 = 32` bits.

**Como uma S-BOX funciona** — exemplo com `S1` e entrada `011011`:

- O **primeiro e o último bit** (`0` e `1` → `01`) formam a **linha**: `01 = 1`.
- Os **4 bits do meio** (`1101`) formam a **coluna**: `1101 = 13`.
- Consulta-se a linha 1, coluna 13 da tabela `S1` → valor `5` → em binário: `0101`.

```
S1(011011) = 0101
```

Cada S-BOX tem sua própria tabela de 4 linhas × 16 colunas (valores de 0 a 15). As
8 tabelas (`S1` a `S8`) são fixas e fazem parte da especificação do DES — são a
etapa de **confusão** não-linear da cifra, essencial para sua segurança (é a única
parte não-linear de todo o algoritmo).

### 6.5. Permutação final da função F (P-BOX): 32 → 32 bits

Após passar pelas 8 S-BOXes, os 32 bits resultantes passam por uma última
permutação (tabela `P`), que **espalha a influência de cada bit** (difusão) antes
do resultado ser combinado com `LEi-1`:

```
P
16  7 20 21
29 12 28 17
 1 15 23 26
 5 18 31 10
 2  8 24 14
32 27  3  9
19 13 30  6
22 11  4 25
```

O resultado dessa permutação **é** a saída da função `F(REi-1, Ki)`.

### 6.6. Fechando a rodada

```
LEi = REi-1
REi = LEi-1 XOR F(REi-1, Ki)
```

Esse processo se repete por **16 rodadas**. Ao final:

1. Faz-se a **troca das metades**: `(LE16, RE16)` → `(RE16, LE16)`.
2. Aplica-se a **permutação final IP⁻¹** (inversa exata da IP), produzindo o texto
   cifrado de 64 bits.

```
IP⁻¹
40  8 48 16 56 24 64 32
39  7 47 15 55 23 63 31
38  6 46 14 54 22 62 30
37  5 45 13 53 21 61 29
36  4 44 12 52 20 60 28
35  3 43 11 51 19 59 27
34  2 42 10 50 18 58 26
33  1 41  9 49 17 57 25
```

---

## 7. Exemplo prático completo

Este exemplo (retirado dos slides, reproduzível no simulador
[simewu.com/des](https://simewu.com/des/)) cifra a frase **"Atacar base norte."**
com a chave hexadecimal `01 23 45 67 89 AB CD EF`.

### 7.1. Preparação

Texto plano em ASCII/hex:

```
41 74 61 63 61 72 20 62 61 73 65 20 6E 6F 72 74 65 2E
```

Como a mensagem tem mais de 64 bits (8 bytes), ela é dividida em **blocos de 64
bits (8 bytes)**. O último bloco incompleto recebe **padding com zeros**.

Primeiro bloco (64 bits) em binário:

```
0100 0001 0111 0100 0110 0001 0110 0011 0110 0001 0111 0010 0010 0000 0110 0010
("Atacar b")
```

Chave em binário:

```
0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
```

### 7.2. Geração das subchaves (resumo)

Após `PC-1`, a chave de 64 bits vira 56 bits:

```
Key after PC-1 = 1111000 0110011 0010101 0100000 1010101 0110011 0011110 0000000
```

Aplicando os deslocamentos e `PC-2` sucessivamente (rodadas 1 a 16), chega-se a
`K1 ... K16`. Exemplos das duas primeiras subchaves:

```
K1  = 000010 110000 001001 100111 100110 110100 100110 100101
K2  = 011010 011010 011001 011001 001001 010110 101000 100110
```

(as demais, `K3` a `K16`, seguem o mesmo processo de deslocamento + `PC-2`.)

### 7.3. Permutação inicial (IP) do bloco

```
Original message (64-bit):
0100 0001 0111 0100 0110 0001 0110 0011 0110 0001 0111 0010 0010 0000 0110 0010

Message after IP (64-bit):
1011 1111 0010 0010 0000 0010 0001 1101 0000 0000 1111 1110 0000 0000 1010 1000
```

Divide-se em:

```
L0 = 1011 1111 0010 0010 0000 0010 0001 1101
R0 = 0000 0000 1111 1110 0000 0000 1010 1000
```

### 7.4. Rodada 1

```
K1     = 000010 110000 001001 100111 100110 110100 100110 100101

E(R0)  = 000000 000001 011111 111100 000000 000001 010101 010000      (expansão de R0)

K1 ⊕ E(R0) = 000010 110001 010110 011011 100110 110101 110011 110101  (XOR com a subchave)

S(K1 ⊕ E(R0)) = 0100 1011 0111 1010 1011 0001 0101 1001              (substituição via S-BOX, 48→32 bits)

f = P(S(...))  = 0110 1111 0101 1001 1110 1000 1100 0100             (permutação P)

L1 = R0 = 0000 0000 1111 1110 0000 0000 1010 1000
R1 = L0 ⊕ f(R0, K1) = 1101 0000 0111 1011 1110 1010 1101 1001
```

### 7.5. Rodada 2

```
K2 = 011010 011010 011001 011001 001001 010110 101000 100110

E(R1) = 111010 100000 001111 110111 111101 010101 011011 110011
K2 ⊕ E(R1) = 100000 111010 010110 101110 110100 000011 110011 010101
S(K2 ⊕ E(R1)) = 0100 0011 0111 1101 1100 1111 0101 0110
f = P(S(...))  = 1101 0111 0011 0111 1111 0000 0110 1100

L2 = R1 = 1101 0000 0111 1011 1110 1010 1101 1001
R2 = L1 ⊕ f(R1, K2) = 1101 0111 1100 1001 1111 0000 1100 0100
```

### 7.6. Rodada 3

```
K3 = 010001 011101 010010 001010 101101 000010 100011 010010

E(R2) = 011010 101111 111001 010011 111110 100001 011000 001001
K3 ⊕ E(R2) = 001011 110010 101011 011001 010011 100011 111011 011011
S(K3 ⊕ E(R2)) = 0010 1000 1001 0001 0000 0011 0010 1110
f = P(S(...))  = 1000 1100 0010 1010 0010 0111 0010 0000

L3 = R2 = 1101 0111 1100 1001 1111 0000 1100 0100
R3 = L2 ⊕ f(R2, K3) = 0101 1100 0101 0001 1100 1101 1111 1001
```

Esse processo se repete até a **rodada 16**, gerando `L16` e `R16`. Depois, faz-se
a troca de metades (`R16` + `L16`) e aplica-se `IP⁻¹`, resultando no texto cifrado
final.

### 7.7. Resultado final

Para a mensagem completa "Atacar base norte." com a chave `01 23 45 67 89 AB CD EF`,
o texto cifrado (em hexadecimal) é:

```
Texto Cifrado = 30 44 35 1B 5A 18 C0 3D EF 5F E5 6B 50 21 1E F3 DF 4E E0 85 9A 96 E9 88
```

> Use o simulador [simewu.com/des](https://simewu.com/des/) para reproduzir esse
> exemplo passo a passo e validar uma implementação própria do DES.

---

## 8. Descriptografia no DES

Um dos motivos pelos quais a cifra de Feistel é tão elegante é que a
**decifração usa exatamente o mesmo algoritmo da cifração** — só muda a **ordem**
em que as subchaves são aplicadas: em vez de `K1, K2, ..., K16`, usa-se
`K16, K15, ..., K1`.

Isso funciona porque, na estrutura de Feistel, cada rodada é "auto-reversível" ao
inverter a ordem das chaves:

```
Cifrando:     LEi = REi-1          REi = LEi-1 ⊕ F(REi-1, Ki)
Decifrando:   RDi = LDi-1          LDi = RDi-1 ⊕ F(LDi-1, K(17-i))
```

Ou seja, a decifração começa com o texto cifrado como entrada (`RD0/LD0`), aplica a
mesma rede de rodadas, mas percorrendo as subchaves na ordem inversa (`K16` primeiro,
`K1` por último), e ao final recupera o texto claro original.

**Importante:** as permutações `IP` e `IP⁻¹` também são aplicadas nas posições
correspondentes (IP no início da decifração, IP⁻¹ no final), pois são inversas
exatas uma da outra.

---

## 9. DES e 3DES

- O **DES é hoje considerado inseguro** por causa do tamanho pequeno da chave
  (56 bits efetivos). A evolução do hardware tornou **ataques de força bruta**
  viáveis.
- Para superar essa limitação **sem descartar os sistemas legados** que já usavam
  DES, foi criado o **3DES (Triplo DES)**.
- O 3DES usa **três chaves de 64 bits** (`K1, K2, K3`) e aplica o DES três vezes em
  sequência, no padrão **Encrypt–Decrypt–Encrypt (EDE)**:

```
Cifração:
  P (64 bits) → DES cifra (K1) → DES decifra (K2) → DES cifra (K3) → C (64 bits)

Decifração (ordem inversa das operações):
  C (64 bits) → DES decifra (K3) → DES cifra (K2) → DES decifra (K1) → P (64 bits)
```

Usar "cifra-decifra-cifra" (em vez de cifrar três vezes seguidas) permite que,
configurando `K1 = K2 = K3`, o 3DES se comporte **exatamente como o DES simples** —
garantindo compatibilidade retroativa com sistemas legados.

---

## 10. Resumo / pontos-chave

- Uma cifra de bloco "ideal" (mapeamento totalmente arbitrário) fica inviável para
  blocos grandes, porque o tamanho da chave cresceria exponencialmente
  (`n × 2^n` bits).
- A **cifra de Feistel** resolve isso combinando **confusão** (S-BOX) e **difusão**
  (P-BOX) em múltiplas rodadas, usando uma estrutura que é **naturalmente
  reversível**.
- O **DES** é uma implementação concreta da cifra de Feistel: 16 rodadas, blocos
  de 64 bits, chave de 64 bits (56 efetivos), com permutações extras `IP`/`IP⁻¹` no
  início e no fim.
- Cada rodada do DES usa uma função `F` que: expande `R` de 32→48 bits (tabela `E`),
  faz XOR com a subchave da rodada, reduz de 48→32 bits via 8 S-BOXes (a única
  parte não-linear da cifra), e permuta o resultado (tabela `P`).
- As **16 subchaves** (`K1`...`K16`, 48 bits cada) são derivadas da chave original
  via `PC-1` (64→56 bits), deslocamentos circulares por rodada, e `PC-2` (56→48 bits).
- A **decifração usa o mesmo algoritmo**, só invertendo a ordem das subchaves
  (`K16` → `K1`).
- O DES é considerado **inseguro atualmente** por causa da chave curta; o **3DES**
  (aplicar DES três vezes em modo EDE com três chaves) foi a solução de transição
  até algoritmos mais modernos como o AES.

## Referências

- Slides "Aula 4" (UniSENAI-PR) — Cifra de Bloco, Cifra de Feistel, DES, 3DES.
- Simulador interativo de DES: https://simewu.com/des/
