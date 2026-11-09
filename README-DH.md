# Opção 9 — Diffie-Hellman + Cifra de César

**Projeto 2:** chat TCP em que **cada mensagem** tem sua própria chave de César, negociada
na hora por **Diffie-Hellman** entre os dois participantes, passando pelo servidor.

> Diffie-Hellman **negocia a chave**; César **cifra a mensagem**. Diffie-Hellman não é uma
> cifra: ele não esconde nada, só permite que os dois lados cheguem ao mesmo número secreto
> trocando apenas valores públicos. A atividade é didática: César, com 25 chaves possíveis,
> não oferece segurança real.

---

## Sumário

1. [Como executar](#1-como-executar)
2. [Parâmetros públicos p e g](#2-parâmetros-públicos-p-e-g)
3. [Nomenclatura: aula × projeto](#3-nomenclatura-aula--projeto)
4. [O que acontece em cada mensagem](#4-o-que-acontece-em-cada-mensagem)
5. [Regras do enunciado e onde são cumpridas](#5-regras-do-enunciado-e-onde-são-cumpridas)
6. [Protocolo: o quadro `D`](#6-protocolo-o-quadro-d)
7. [Decisões de implementação](#7-decisões-de-implementação)
8. [Demonstração e testes](#8-demonstração-e-testes)
9. [Limitações](#9-limitações)
10. [Errata do slide](#10-errata-do-slide)

---

## 1. Como executar

São três terminais, todos a partir da raiz do projeto:

```bash
python server.py          # terminal 1
python client.py          # terminal 2 (Alice) -> opção 9
python client.py          # terminal 3 (Bob)   -> opção 9
```

Para o vídeo, há dois scripts que rodam sozinhos:

```bash
python scripts/verificar_parametros_dh.py --pausar   # justifica a escolha de p e g (§2)
python scripts/demonstracao_dh.py                    # as 5 mensagens consecutivas (§8)
```

O `--pausar` espera um Enter entre as partes, para dar tempo de explicar cada uma.

Na opção 9 **não se digita chave**: ela é negociada a cada mensagem. Os dois clientes
precisam escolher a opção 9. O servidor aceita **somente 2 participantes**, e uma terceira
conexão é recusada com o aviso *"Sala cheia"*.

Ao escolher a opção 9, o cliente mostra p e g e entra na conversa na hora (a prova de que
p e g são adequados está no script de verificação e nos testes, §2). Depois:

- **Sozinho na sala:** aparece *"Aguardando o outro participante para iniciar a conversa"*.
  Uma mensagem digitada nesse estado é **recusada** com o aviso de que não há ninguém para
  recebê-la; nenhuma negociação começa.
- **Quando o outro entra:** *"conversa iniciada"* aparece nos dois terminais e as mensagens
  passam a ser negociadas.
- **Se o outro sai:** a negociação em andamento é cancelada, as mensagens que esperavam na
  fila são descartadas (com aviso) e o cliente volta a aguardar. Quem entrar depois começa
  uma **conversa nova**, sem herdar o k da conversa anterior.

Para a demonstração automática das 5 mensagens (ver §8):

```bash
python scripts/demonstracao_dh.py
```

---

## 2. Parâmetros públicos p e g

O enunciado permite deixar p e g fixos, **desde que sejam adequados para Diffie-Hellman**.
Os números da aula (p = 353, g = 3) servem para fazer a conta no quadro, mas não são
adequados: o próprio programa de força bruta da aula descobre a chave privada em no máximo
352 tentativas.

### p: primo de 2048 bits do RFC 3526 (grupo 14)

Usamos o *2048-bit MODP Group* do RFC 3526, padronizado e usado em IPsec/IKE, SSH e TLS. Ele
tem **617 dígitos decimais** e está no código exatamente como publicado no RFC
(`cifras/diffie_hellman.py`, `P_HEX_RFC3526_GRUPO14`).

Esse p é um **primo seguro**: `p = 2q + 1`, com **q também primo**. Isso não é detalhe: é
o que permite aplicar o teste de raiz primitiva da aula a um número desse tamanho. O teste
exige fatorar φ(p) = p − 1, e fatorar um número qualquer de 2048 bits é inviável. Para um
primo seguro, a fatoração é imediata: **φ(p) = 2 · q**.

### g = 11: a menor raiz primitiva de p

A aula define g como **raiz primitiva** de p. O RFC 3526 usa g = 2, mas **2 não é raiz
primitiva** deste p (2^q mod p = 1, e o mesmo vale para 3, 4, …, 10). O RFC escolhe 2 de
propósito, para gerar o subgrupo de ordem q. Como a aula pede raiz primitiva, usamos a
menor delas, **g = 11**, verificada pelo mesmo método do slide *"Algoritmo de exponenciação
modular"*:

| Passo da aula | Exemplo da aula (p = 353, g = 3) | Neste projeto (p de 2048 bits, g = 11) |
|---|---|---|
| 1. Calcular φ(p) | φ(353) = 352 | φ(p) = p − 1 |
| 2. Fatorar φ(p) | 352 = 2⁵ × 11 | p − 1 = 2 × q (q primo) |
| 3. g^(φ/f) mod p para cada fator f | 3¹⁷⁶ = 352 ≠ 1; 3³² = 140 ≠ 1 | 11^q = p − 1 ≠ 1; 11² = 121 ≠ 1 |
| Conclusão | 3 é raiz primitiva | 11 é raiz primitiva |

### Script de verificação

Como p e g são **constantes**, provar que são adequados é algo que se faz uma vez, e não a
cada vez que o chat abre. A prova está em `scripts/verificar_parametros_dh.py` (e nos
testes), feito para ser mostrado no vídeo. Usa só as funções do projeto (`exp_mod`,
`eh_provavel_primo`, `eh_raiz_primitiva`) e segue o roteiro da aula:

1. **Por que não p = 353 e g = 3.** Roda a força bruta da aula: o Darth acha CpB = 97 em
   97 tentativas (frações de milissegundo) e calcula K = 160. Depois mede a velocidade da
   máquina contra o p do chat: ~10⁶¹⁶ tentativas no pior caso, mais de 10⁶⁰⁰ anos. Mesmo os
   algoritmos O(√N) citados na aula precisariam de ~10³⁰⁸ operações.
2. **Por que este p.** Mostra o hexadecimal exatamente como no RFC, confere os 2048 bits e
   roda Miller-Rabin em p e em q (primo seguro).
3. **Por que g = 11.** Reaplica o método ao exemplo da aula (3 é e 6 não é raiz primitiva de
   353) e depois testa g = 2, 3, …, 11 no p do chat: de 2 a 10, g^q mod p = 1; 11 é a
   primeira raiz primitiva.
4. **Conclusão:** "parâmetros ADEQUADOS". O script sai com código 0, ou 1 se algo falhar.

Trecho da saída:

```
      g  g^q mod p        g^2 mod p   resultado
      2  1                        4   NÃO é (g^q mod p = 1)
      3  1                        9   NÃO é (g^q mod p = 1)
     ...
     10  1                      100   NÃO é (g^q mod p = 1)
     11  p - 1                  121   É raiz primitiva
```

### Valores privados

Cada valor privado é sorteado no intervalo da aula, **2 ≤ a ≤ p − 2**, com o módulo
`secrets` (gerador criptográfico do sistema operacional). O módulo `random` não serve: ele é
previsível a partir de algumas saídas observadas.

---

## 3. Nomenclatura: aula × projeto

O código segue os nomes do enunciado do projeto. A correspondência com os slides:

| Projeto | Aula (Bob / Alicie) | Público? |
|---|---|---|
| p, g | p, g | sim |
| a (remetente) | CpB | **não** |
| b (destinatário) | CpA | **não** |
| A = gᵃ mod p | Yb = g^CpB mod p | sim |
| B = gᵇ mod p | Ya = g^CpA mod p | sim |
| s = Bᵃ mod p | K = Ya^CpB mod p | **não** |
| s = Aᵇ mod p | K = Yb^CpA mod p | **não** |
| k = 1 + (s mod 25) | *(passo extra do projeto: vira a chave de César)* | **não** |

Com os números da aula (CpB = 97, CpA = 233): A = 40, B = 248, s = 160, **k = 11**. Esses
valores são verificados nos testes.

---

## 4. O que acontece em cada mensagem

```
 REMETENTE (Alice)                 SERVIDOR                  DESTINATÁRIO (Bob)
 1. sorteia a NOVO
 2. A = g^a mod p
 3. ── D "A <id> <tent> <A>" ──►  imprime, repassa  ──►
                                                         1. sorteia b NOVO
                                                         2. B = g^b mod p
                                                         4. s = A^b mod p
                                                         5. k = 1 + (s mod 25)
                                                         6. k igual ao anterior?
                                                         7. imprime k
    ◄── D "B <id> <B>" ─────────  imprime, repassa  ◄──
 4. s = B^a mod p
 5. k = 1 + (s mod 25)
 6. k igual ao anterior? ── sim ──► volta ao passo 1 com a NOVO
 7. imprime k
 8. C = César(texto, k)
    ── M "<C>" ────────────────►  9. imprime C ──────►
                                     repassa           10. texto = César⁻¹(C, k)
                                                           imprime o texto original
```

Isso se repete **inteiro** a cada mensagem, mesmo quando o texto é igual ao da anterior.

Trecho real do terminal do remetente (de `docs/demonstracao-dh.txt`):

```
=== MENSAGEM #2 | negociação dd61e374673a4d8a | tentativa 1 | você é o REMETENTE ===
 [1] valor privado NOVO:   a = 678490198839...939389302544 (615 dígitos)   (fica só neste terminal)
 [2] valor público:        A = g^a mod p = 279220226031...604578262190 (617 dígitos)
 [3] enviando A ao destinatário pelo servidor...
 [3] B recebido do destinatário: B = 284458906654...634565227226 (617 dígitos)
 [4] segredo compartilhado:  s = B^a mod p = 228927745566...125133992362 (617 dígitos)
 [5] chave de César:         k = 1 + (s mod 25) = 1 + 12 = 13
 [6] verificação: mensagem anterior usou k = 3 -> chave aceita
 [7] CHAVE DESTA MENSAGEM:   k = 13
```

Os números de 617 dígitos aparecem resumidos (começo…fim e tamanho). Isso basta para
comparar o mesmo valor em dois terminais: o `s` do remetente e o do destinatário são
idênticos.

---

## 5. Regras do enunciado e onde são cumpridas

| Regra | Como é garantida | Onde |
|---|---|---|
| p e g fixos e **adequados** | Primo seguro de 2048 bits (RFC 3526) e g raiz primitiva; provado uma vez, não a cada execução | `scripts/verificar_parametros_dh.py`, testes |
| Valores privados **renovados a cada mensagem** | `gerar_privado()` é chamado no início de **toda** negociação, inclusive nas repetições | `SessaoDH._iniciar_negociacao()`, `_receber_A()` |
| Chave da mensagem anterior **não reutilizada diretamente** | Cada mensagem deriva k de um segredo novo; nada é guardado de uma negociação para a outra além do último k, que serve só para comparar | `sessao_dh.py` |
| k **diferente da mensagem imediatamente anterior** | Passo 6 nos dois lados; se repetir, nova negociação com valores privados novos. Um k pode voltar depois de outras mensagens | `SessaoDH._chave_repetida()` |
| a, b, s e k **nunca transmitidos** | Os quadros D só carregam A ou B; o quadro M só carrega o texto cifrado | teste `teste_segredos_nunca_trafegam` |
| Servidor **só repassa e imprime** o cifrado | `server.py` não importa `cifras/` nem `sessao_dh`: não tem como calcular k | teste `teste_servidor_nao_importa_nada_de_diffie_hellman` |
| Cálculos de DH **feitos pelos alunos** | `exp_mod()` própria (*square-and-multiply*); sem `pow()` nativo nem biblioteca de troca de chaves | teste `teste_codigo_do_chat_nao_usa_pow_nem_biblioteca_de_troca_de_chaves` |

### Exponenciação modular

Na aula, `expMod(base, i, mod)` era chamada com expoentes até 352. Aqui o expoente tem
2048 bits, e multiplicar a base "expoente vezes" levaria mais que a idade do universo.
`exp_mod()` usa **elevar ao quadrado e multiplicar**: percorre os bits do expoente, eleva a
base ao quadrado a cada bit e multiplica no resultado quando o bit vale 1, reduzindo mod p a
cada passo. São cerca de 4096 multiplicações por exponenciação.

```
3^5 mod 1000, com 5 = 101 em binário:
  bit 1 -> resultado = 1 * 3  = 3     base = 3^2 = 9
  bit 0 -> resultado = 3              base = 9^2 = 81
  bit 1 -> resultado = 3 * 81 = 243
```

---

## 6. Protocolo: o quadro `D`

O protocolo de quadros (`protocolo.py`) ganhou um quarto tipo:

| Tipo | Conteúdo | Quem envia |
|---|---|---|
| `M` | texto cifrado com César | cliente |
| `S` | aviso do servidor | só o servidor |
| `C` | comando: `/sair`; e `/participantes N` (só o servidor) | cliente / servidor |
| **`D`** | **negociação Diffie-Hellman: só valores públicos** | cliente |

```
D "A <id> <tentativa> <A>"     remetente -> destinatário
D "B <id> <B>"                 destinatário -> remetente
```

`<id>` é um identificador aleatório de 16 caracteres hexadecimais, único por negociação.
Serve para casar o B com o A certo e para resolver colisões (§7). O servidor imprime o
quadro D (é o que o Darth, escutando a rede, também veria) e o repassa sem interpretá-lo.

---

## 7. Decisões de implementação

**Quem decide que a chave repetiu.** Os dois lados calculam o mesmo k e guardam o mesmo k
anterior, então chegam à mesma conclusão **sem conversar**. O destinatário responde B mesmo
assim (o remetente precisa de B para calcular k e ver a repetição) e descarta a chave; o
remetente recomeça do passo 1. Isso só funciona se as negociações forem **estritamente
sequenciais**, para que "a mensagem anterior" seja a mesma nos dois terminais. Daí as duas
regras seguintes.

**Fila.** Se o usuário digitar enquanto uma negociação está em andamento, a mensagem
espera a vez.

**Colisão.** Se os dois apertarem Enter quase ao mesmo tempo, cada um envia seu A antes de
receber o do outro. Vence a negociação de **menor `<id>`**. Os dois comparam os mesmos dois
ids, então concordam sobre quem vai primeiro sem trocar nada a mais. O perdedor descarta o
próprio A (nunca chegou a calcular s com ele), atende o vencedor e recomeça depois.

**Valores públicos degenerados.** Um A ou B igual a 0, 1 ou p − 1 é recusado. Com A = 1, por
exemplo, s = 1ᵇ mod p = 1 para qualquer b, e a chave ficaria conhecida por qualquer um. Um
valor legítimo gˣ com 2 ≤ x ≤ p − 2 nunca cai nesses casos.

**Sala de 2.** O passo 6 fala da "mensagem anterior entre esses clientes", o que pressupõe
uma conversa a dois. O servidor recusa a terceira conexão (`MAX_CLIENTES = 2`).

**Quantos estão na sala.** A cada entrada e saída, o servidor envia a todos o quadro de
controle `C "/participantes N"`. Sem isso, quem entra numa sala vazia não sabe que está
sozinho (o aviso *"Alguem entrou"* só vai para quem já estava lá): o A enviado se perderia
e a sessão ficaria esperando para sempre um B que não vem. Com a contagem:

| Situação | O que a sessão faz |
|---|---|
| N = 1 (sozinho) | Recusa mensagens digitadas, com aviso; não negocia |
| N passa de 2 para 1 (o outro saiu) | Cancela a negociação em andamento, descarta a fila (com aviso), zera o estado |
| N passa a 2 (o outro entrou) | Começa uma conversa nova: k anterior e numeração zerados, porque o passo 6 vale entre *esses* dois clientes |

É um quadro **C** (e não um aviso de texto **S**) de propósito: o cliente decide pelo tipo
do quadro, não lendo o conteúdo. E um cliente não consegue forjá-lo, porque o servidor ignora
comandos desconhecidos vindos de clientes. Isso continua sendo só controle de sala: o
servidor não calcula nem decifra nada.

**Sessão sem socket.** `SessaoDH` recebe as funções `enviar(tipo, texto)` e `exibir(linha)`.
O `client.py` liga essas funções ao socket e ao terminal; os testes ligam duas sessões
diretamente, sem rede.

---

## 8. Demonstração e testes

### Demonstração (entrega)

`scripts/demonstracao_dh.py` sobe o `server.py` e **dois `client.py` reais**, escolhe a
opção 9 nos dois, digita 6 mensagens (5 consecutivas da Alice, incluindo o mesmo texto duas
vezes, e uma resposta do Bob) e grava os três terminais em `docs/demonstracao-dh.txt`. No
fim, imprime uma tabela extraída dos terminais e **confere** os itens da entrega:

```
RESUMO (extraído dos três terminais)
 #  de     negociações  k Alice  k Bob  cifrado no SERVIDOR     original recuperado no destinatário
 1  alice            1        3      3  ROD ERE                 OLA BOB
 2  alice            1       13     13  BYN OBO                 OLA BOB
 3  alice            1        5      5  FYFHFW GFXJ STWYJ.      ATACAR BASE NORTE.
 4  alice            1       14     14  OG 10V, GSA TOZHO       AS 10H, SEM FALTA
 5  alice            1       11     11  NZYQTCXL?               CONFIRMA?
 6  bob              1       21     21  XJIADMHVYJ, VGDXZ!      CONFIRMADO, ALICE!
```

| Item da entrega | Onde aparece |
|---|---|
| Uma nova negociação para cada mensagem | Cabeçalho `=== MENSAGEM #n \| negociação <id>` nos clientes, linhas `[DH repassado]` no servidor |
| A mesma chave nos dois clientes | `[7] CHAVE DESTA MENSAGEM: k = …` nos dois terminais, colunas *k Alice* e *k Bob* |
| Chaves diferentes entre mensagens consecutivas | Linha `[6] verificação` e a coluna de k (um k pode voltar depois de outras mensagens, o que é permitido) |
| Texto cifrado no terminal do servidor | `[CIFRADO recebido] …` |
| Texto original recuperado no destinatário | `[10] … TEXTO ORIGINAL (mensagem #n): …` |

As chaves mudam a cada execução, porque os valores privados são aleatórios.

### Testes

```bash
python tests/test_diffie_hellman.py    # 29 testes, sem rede
python tests/test_integracao_dh.py     # 5 testes com o server.py real
python -m doctest cifras/diffie_hellman.py
```

Os testes reproduzem todos os números da aula (troca normal e ataque *man-in-the-middle*),
comparam o teste de raiz primitiva com a definição por enumeração para p = 353, conferem
`exp_mod` contra um gabarito independente em números de 2048 bits e cobrem: chave repetida
forçando renegociação, colisão, fila, mensagem sem negociação, valores públicos degenerados,
segredos que nunca aparecem na rede, mensagem recusada para quem está sozinho, saída do outro
participante no meio de uma negociação e conversa nova sem herdar o k anterior.

---

## 9. Limitações

- **Man-in-the-middle ativo.** Como a aula mostra (Darth com Xd1 e Xd2), Diffie-Hellman sem
  autenticação é vulnerável a quem consegue alterar o tráfego. Aqui o próprio servidor está
  nessa posição: ele **não** faz isso (só repassa), mas um servidor adulterado poderia. A
  defesa (assinaturas digitais e certificados) é assunto das próximas aulas.
- **César.** Com apenas 25 chaves, qualquer texto cifrado cai por força bruta, por mais forte
  que seja a negociação. O enunciado reconhece isso: a atividade é didática.
- **g raiz primitiva.** Usar uma raiz primitiva (exigência da aula) em vez de um gerador do
  subgrupo de ordem q (escolha do RFC) revela 1 bit do valor privado, a sua paridade, para
  quem observa o valor público. Com valores privados de ~2048 bits, isso não tem efeito
  prático.

---

## 10. Errata do slide

O slide *"Algoritmo de exponenciação modular"* afirma que **3³² mod 353 = 294**. O valor
correto é **140** (294 é 3¹¹ mod 353). A conclusão do slide não muda, porque 140 ≠ 1 e 3
continua sendo raiz primitiva de 353. O teste `teste_raiz_primitiva_exemplos_da_aula`
registra isso.

---

## Referências

- T. Kivinen, M. Kojo. *RFC 3526 — More Modular Exponential (MODP) Diffie-Hellman groups for
  Internet Key Exchange (IKE)*, 2003, seção 3.
- Material da disciplina: *Diffie-Hellman* (slides da aula) e enunciado *Projeto: chat TCP
  com Diffie-Hellman e cifra de César*.
