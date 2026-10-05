# AES-128 (Advanced Encryption Standard) — Guia de Estudo

> Guia da cifra `cifras/aes.py` (opção **8** do menu do cliente). Segue o FIPS-197.
> Toda a aritmética é feita **bit a bit**, sem biblioteca de criptografia: a S-BOX
> e o Rcon são **calculados**, não copiados de tabelas.

## Índice

1. [Visão geral](#1-visão-geral)
2. [O estado 4×4](#2-o-estado-44)
3. [Aritmética em GF(2⁸)](#3-aritmética-em-gf28)
4. [S-BOX](#4-s-box)
5. [Expansão de chave (w[0]..w[43]) e Rcon](#5-expansão-de-chave-w0w43-e-rcon)
6. [As operações da rodada](#6-as-operações-da-rodada)
7. [Cifração e a rodada final](#7-cifração-e-a-rodada-final)
8. [Decifração](#8-decifração)
9. [Uso no chat](#9-uso-no-chat)
10. [Como testar](#10-como-testar)
11. [Erros comuns](#11-erros-comuns-cobertos-pelos-testes)

---

## 1. Visão geral

| Parâmetro | AES-128 |
|---|---|
| Bloco | 128 bits = **16 bytes** |
| Chave | 128 bits = **16 bytes** |
| Rodadas | **10** |
| Chaves de rodada | 11 (`w[0]..w[43]`, 4 palavras de 4 bytes cada) |

Ao contrário do DES (rede de Feistel, que transforma só metade do bloco por rodada), o AES
é uma rede de **substituição-permutação**: todos os 16 bytes mudam em toda rodada.

```
AddRoundKey(chave 0)
rodadas 1..9 :  SubBytes → ShiftRows → MixColumns → AddRoundKey
rodada 10    :  SubBytes → ShiftRows →              AddRoundKey     (sem MixColumns!)
```

## 2. O estado 4×4

Os 16 bytes entram na matriz **por coluna** (`estado[linha][coluna] = bloco[linha + 4·coluna]`):

```
bytes b0 b1 ... b15           b0  b4  b8  b12
                      ──►     b1  b5  b9  b13
                              b2  b6  b10 b14
                              b3  b7  b11 b15
```

Cada coluna é uma palavra `w` de 4 bytes. Funções: `_bytes_para_estado`, `_estado_para_bytes`.

## 3. Aritmética em GF(2⁸)

Cada byte é um polinômio de grau ≤ 7 com coeficientes 0/1: `0x57 = 0101 0111 = x⁶+x⁴+x²+x+1`.

- **Soma = XOR.**
- **Multiplicação** = produto de polinômios reduzido por `m(x) = x⁸+x⁴+x³+x+1` (`0x11B`).

**`_xtime(b)`** multiplica por `x` (0x02): desloca 1 bit à esquerda e, se o bit 7 estava ligado,
faz XOR com `0x1B` (o bit 8 some no corte, sobra só `0x11B ⊕ 0x100 = 0x1B`).

```
0x57 → 0101 0111 << 1 = 1010 1110 = 0xAE          (sem estouro)
0xAE → 1010 1110 << 1 = 1 0101 1100 → 0x5C ⊕ 0x1B = 0x47   (estourou)
```

**`_mult_gf(a, b)`** é "shift-and-add": para cada bit ligado de `b`, soma (XOR) o `a` atual; depois `a ← xtime(a)`.

```
0x57 · 0x13   (0x13 = 1 + x + x⁴)
  = 0x57 ⊕ xtime(0x57) ⊕ xtime⁴(0x57)
  = 0x57 ⊕ 0xAE ⊕ 0x07 = 0xFE       (exemplo da seção 4.2.1 do FIPS-197)
```

## 4. S-BOX

`S(b)` em dois passos (`_calcular_sbox_byte`):

1. `b ← b⁻¹` em GF(2⁸) (`_inverso_gf`; o inverso de 0 é 0 por convenção);
2. transformação afim, **bit a bit**:
   `b'ᵢ = bᵢ ⊕ b₍ᵢ₊₄₎ ⊕ b₍ᵢ₊₅₎ ⊕ b₍ᵢ₊₆₎ ⊕ b₍ᵢ₊₇₎ ⊕ cᵢ`, índices módulo 8, `c = 0x63`.

Primeira linha da tabela gerada: `63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76`.
A **S-BOX inversa** é só a tabela lida de trás para frente (`SBOX_INV[S[b]] = b`).

## 5. Expansão de chave (w[0]..w[43]) e Rcon

```
w[0..3]  = a chave (4 bytes por palavra)
para i = 4..43:
    temp = w[i-1]
    se i % 4 == 0:
        temp = SubWord(RotWord(temp)) ⊕ (Rcon[i/4], 0, 0, 0)
    w[i] = w[i-4] ⊕ temp
```

- **RotWord**: `[a0 a1 a2 a3] → [a1 a2 a3 a0]`
- **SubWord**: S-BOX em cada byte
- **Rcon**: `01 02 04 08 10 20 40 80 1B 36` — começa em `01` e dobra (`xtime`) a cada rodada
  (`0x80 · 2` estoura e vira `0x1B`).

Exemplo do FIPS-197 (A.1), `i = 4`: `w[3] = 09cf4f3c` → RotWord `cf4f3c09` → SubWord `8a84eb01`
→ ⊕ Rcon `8b84eb01` → `w[4] = w[0] ⊕ 8b84eb01 = a0fafe17`.

Chaves de rodada para `2b7e1516 28aed2a6 abf71588 09cf4f3c`:

| Rodada | w[4r] w[4r+1] w[4r+2] w[4r+3] |
|---|---|
| 0 | 2b7e1516 28aed2a6 abf71588 09cf4f3c |
| 1 | a0fafe17 88542cb1 23a33939 2a6c7605 |
| 2 | f2c295f2 7a96b943 5935807a 7359f67f |
| 3 | 3d80477d 4716fe3e 1e237e44 6d7a883b |
| 4 | ef44a541 a8525b7f b671253b db0bad00 |
| 5 | d4d1c6f8 7c839d87 caf2b8bc 11f915bc |
| 6 | 6d88a37a 110b3efd dbf98641 ca0093fd |
| 7 | 4e54f70e 5f5fc9f3 84a64fb2 4ea6dc4f |
| 8 | ead27321 b58dbad2 312bf560 7f8d292f |
| 9 | ac7766f3 19fadc21 28d12941 575c006e |
| 10 | d014f9a8 c9ee2589 e13f0cc8 b6630ca6 |

## 6. As operações da rodada

- **SubBytes** — troca cada byte do estado pela S-BOX.
- **ShiftRows** — a linha `l` rotaciona `l` posições à **esquerda** (linha 0 fica parada).
- **MixColumns** — cada coluna é multiplicada por uma matriz fixa em GF(2⁸):

```
| s'0 |   | 02 03 01 01 |   | s0 |      s'0 = 02·s0 ⊕ 03·s1 ⊕ 01·s2 ⊕ 01·s3
| s'1 | = | 01 02 03 01 | · | s1 |      s'1 = 01·s0 ⊕ 02·s1 ⊕ 03·s2 ⊕ 01·s3
| s'2 |   | 01 01 02 03 |   | s2 |      ...
| s'3 |   | 03 01 01 02 |   | s3 |
```

  Exemplo: coluna `db 13 53 45` → `8e 4d a1 bc`. Aqui
  `s'0 = 02·db ⊕ 03·13 ⊕ 53 ⊕ 45 = 8e`.
- **AddRoundKey** — XOR do estado com a chave da rodada (coluna `c` = palavra `w[4r+c]`).

Ver `_multiplicar_coluna` em `cifras/aes.py`: cada produto é um `_mult_gf` explícito.

## 7. Cifração e a rodada final

Exemplo do Apêndice B do FIPS-197 (texto `3243f6a8 885a308d 313198a2 e0370734`):

| Etapa | Estado |
|---|---|
| entrada | `3243f6a8885a308d313198a2e0370734` |
| AddRoundKey (chave 0) | `193de3bea0f4e22b9ac68d2ae9f84808` |
| rodada 1 — SubBytes | `d42711aee0bf98f1b8b45de51e415230` |
| rodada 1 — ShiftRows | `d4bf5d30e0b452aeb84111f11e2798e5` |
| rodada 1 — MixColumns | `046681e5e0cb199a48f8d37a2806264c` |
| rodada 1 — AddRoundKey | `a49c7ff2689f352b6b5bea43026a5049` |
| ... | |
| rodada 10 — SubBytes | `e9098972cb31075f3d327d94af2e2cb5` |
| rodada 10 — ShiftRows | `e9317db5cb322c723d2e895faf090794` |
| rodada 10 — AddRoundKey | `3925841d02dc09fbdc118597196a0b32` ← cifrado |

A **rodada 10 não tem MixColumns**. O motivo é que, depois da última rodada, o MixColumns
não acrescentaria segurança (um atacante o desfaria de graça) e só complicaria a simetria
da decifração.

Para ver tudo isso rodando, `_cifrar_bloco(bloco, w, rastro=[])` preenche `rastro`
com `(nome_da_etapa, estado_em_hex)`.

## 8. Decifração

Começa pelo texto cifrado e pela **última** chave de rodada, desfazendo na ordem inversa:

```
AddRoundKey(chave 10)
rodadas 9..1 :  InvShiftRows → InvSubBytes → AddRoundKey(r) → InvMixColumns
final        :  InvShiftRows → InvSubBytes → AddRoundKey(0)
```

- **InvShiftRows**: a linha `l` rotaciona `l` posições à **direita**.
- **InvSubBytes**: S-BOX inversa.
- **InvMixColumns**: matriz inversa em GF(2⁸): `0E 0B 0D 09 / 09 0E 0B 0D / 0D 09 0E 0B / 0B 0D 09 0E`.
- O `InvMixColumns` vem **depois** do `AddRoundKey` e não existe na etapa final.

## 9. Uso no chat

- Opção **8 — Cifra AES** no menu do cliente.
- **Chave**: até 16 caracteres ASCII (completada com zeros à direita) **ou** 32 dígitos
  hexadecimais, com ou sem espaços, ex.: `2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`.
- O texto (ASCII) é dividido em blocos de 16 bytes, modo **ECB**, último bloco completado com zeros.
- O criptograma (bytes 0–255) trafega em **Base64** para respeitar a regra ASCII-only da rede.
  O servidor só repassa o Base64 e nunca vê a chave.

## 10. Como testar

```bash
python tests/test_aes.py
```

Conferência manual no site da disciplina, **https://simewu.com/aes/**: AES-128, modo ECB,
chave e texto em hexadecimal. Para um texto ASCII `Atacar base nort` (16 bytes) com a chave hex
acima, o criptograma exibido em hexadecimal deve coincidir com os bytes do Base64 mostrados no chat.

## 11. Erros comuns (cobertos pelos testes)

| Erro | Teste que o pega |
|---|---|
| MixColumns também na rodada 10 | `teste_erro_rodada_final_nao_tem_mix_columns` |
| InvMixColumns na etapa final / ordem errada na decifração | `teste_erro_decifracao_final_nao_tem_inv_mix_columns` |
| ShiftRows para o lado errado | `teste_shift_rows_e_inversa`, vetores do FIPS |
| Esquecer a redução por `0x1B` em `xtime` | `teste_xtime_so_estoura_com_bit_7`, `teste_mult_gf_*` |
| Rcon errado ou esquecido, RotWord/SubWord omitidos | `teste_expansao_chave_fips_a1_*` |
| Constante afim `0x63` errada | `teste_sbox_valores_conhecidos` |
| Estado montado por linha em vez de coluna | `teste_estado_e_por_coluna` |
| Último bloco sem padding | `teste_tamanho_do_criptograma_e_multiplo_de_16_bytes` |
| Chave errada / Base64 lixo derrubando o cliente | `teste_decifrar_*_nao_derruba_o_cliente` |
