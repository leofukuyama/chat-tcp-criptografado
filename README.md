# Chat TCP com Criptografia Clássica

**Disciplina:** Cibersegurança — 8º semestre
**Trabalho:** Implementação de um sistema de chat cliente/servidor sobre TCP com cifragem
fim-a-fim por cifras clássicas, transporte restrito a ASCII e servidor sem acesso ao texto claro.
**Linguagem:** Python 3.12 (somente biblioteca padrão — `socket`, `threading`, `unicodedata`)

---

## Resumo

Este projeto implementa um chat multiusuário sobre TCP em que **a confidencialidade é
responsabilidade exclusiva dos pontos terminais**. O servidor atua como um *relay* cego:
encaminha bytes sem jamais chamar `cifrar()` ou `decifrar()`, e sem nunca ter posse de
chave. A cifra e a chave são acordadas **fora de banda** entre os participantes e
configuradas localmente em cada cliente.

Sobre esse esqueleto foram construídas três camadas de engenharia que constituem o
conteúdo técnico do trabalho:

1. **Um protocolo de aplicação com enquadramento explícito** (`protocolo.py`), que resolve o
   fato de TCP ser um fluxo de bytes e não de mensagens, e que carrega um campo de **tipo**
   — o que elimina por construção a falsificação de avisos do servidor.
2. **Uma política de charset ASCII com defesa em profundidade** (`ascii_puro.py`), com três
   pontos de verificação independentes, sendo o do servidor um *choke point* que vale
   mesmo contra um cliente adulterado.
3. **Cinco modos de transmissão plugáveis** (`cifras/`), obedecendo a um contrato comum,
   de modo que o núcleo de rede desconhece qual cifra está em uso.

A suíte de verificação contém **147 testes** (unitários, de propriedade e de integração com
sockets reais) e **doctests executáveis** embutidos nos módulos. Todos passam na versão
corrente.

---

## Sumário

- [1. Objetivo e escopo](#1-objetivo-e-escopo)
- [2. Arquitetura do sistema](#2-arquitetura-do-sistema)
- [3. Modelo de ameaças](#3-modelo-de-ameaças)
- [4. Protocolo de aplicação](#4-protocolo-de-aplicação)
- [5. Política de charset: ASCII estrito](#5-política-de-charset-ascii-estrito)
- [6. Catálogo de cifras](#6-catálogo-de-cifras)
- [7. Concorrência e ciclo de vida das conexões](#7-concorrência-e-ciclo-de-vida-das-conexões)
- [8. Execução](#8-execução)
- [9. Verificação e testes](#9-verificação-e-testes)
- [10. Limitações conhecidas](#10-limitações-conhecidas)
- [11. Estrutura de arquivos](#11-estrutura-de-arquivos)
- [12. Referências](#12-referências)

---

## 1. Objetivo e escopo

### 1.1 Requisitos funcionais

| # | Requisito | Onde é atendido |
|---|---|---|
| R1 | Chat TCP multiusuário, cliente/servidor | `server.py`, `client.py` |
| R2 | Mensagens cifradas antes de deixarem o cliente | `client.py::write()` |
| R3 | Servidor não deve ter acesso ao conteúdo | `server.py::broadcast_raw()` |
| R4 | Escolha da cifra e da chave pelo usuário | `client.py::escolher_cifra()` |
| R5 | Cifras: César, monoalfabética, Playfair, Vigenère, e modo aberto | `cifras/` |
| R6 | Normalização: maiúsculas, `Á→A`, `Ç→C`, pontuação preservada | `ascii_puro.normalizar()` |
| R7 | **Apenas ASCII (0–127) circula na rede** | `ascii_puro.py` (3 camadas) |
| R8 | O sistema nunca cai por causa de um caractere inesperado | tratamento de erro em todas as bordas |

### 1.2 Não-objetivos

O trabalho é **didático**. As cifras implementadas são de interesse histórico e
**não oferecem confidencialidade contra um adversário moderno** (ver §6.7). Não há
negociação de chave, integridade criptográfica, autenticação de entidade nem sigilo
persistente. Essas ausências são deliberadas e discutidas em §3 e §10, não acidentais.

---

## 2. Arquitetura do sistema

### 2.1 Visão em blocos

```
   CLIENTE A                        SERVIDOR                       CLIENTE B
 ┌───────────────┐               ┌──────────────┐               ┌───────────────┐
 │ input()       │               │              │               │  print()      │
 │   ↓           │               │  relay cego  │               │    ↑          │
 │ ascii_puro    │  ← camada 1   │              │               │  cifras.*     │
 │   .preparar() │               │  NÃO decifra │               │   .decifrar() │
 │   ↓           │               │  NÃO tem     │               │    ↑          │
 │ cifras.*      │               │    chave     │               │  protocolo    │
 │   .cifrar()   │               │              │               │ .Desempacotador
 │   ↓           │               │  camada 3 →  │               │    ↑          │
 │ protocolo     │  ← camada 2   │  ascii_puro  │               │               │
 │  .empacotar() │               │  .decodificar│               │               │
 └──────┬────────┘               └──────┬───────┘               └───────┬───────┘
        │      M0025DWDTXH DR ...       │     M0025DWDTXH DR ...        │
        └──────────────────────────────►│──────────────────────────────►│
                     TCP                │            TCP
                                        │
                              stdout do servidor:
                              [CIFRADO recebido] DWDTXH DR DPDQKHFHU, 05K!
                              (só o criptograma — prova de que não lê o conteúdo)
```

### 2.2 Princípios de projeto

**(a) Separação estrita entre transporte e criptografia.**
`server.py` não importa nada de `cifras/`. Essa ausência de dependência é a materialização
arquitetural do requisito R3: não é uma promessa no comentário, é uma impossibilidade
estrutural — o servidor não tem a função disponível para chamar.

**(b) Ponto único de verdade.**
Toda decisão sobre charset vive em `ascii_puro.py`; `client.py` e `server.py` nunca chamam
`.encode()` / `.decode()` diretamente. Na versão anterior do projeto existiam **10 chamadas
de `encode("utf-8")`/`decode("utf-8")` espalhadas** entre os dois arquivos, nenhuma
acompanhada de validação — cada uma era uma oportunidade independente de esquecer a regra.

**(c) Contrato uniforme de cifra.**
Todo módulo em `cifras/` expõe exatamente três funções (§6.1). O `client.py` manipula um
módulo opaco (`modulo.cifrar(...)`), o que torna a adição de uma nova cifra uma mudança
de **duas linhas** em `cifras/registro.py`.

**(d) Anonimato por ausência.**
Não existe apelido no protocolo. Não há *handshake* de identidade. O endereço IP:porta de
quem conectou aparece **apenas no log local do servidor**, nunca é transmitido a outro
cliente. Os avisos de entrada e saída são textos fixos e genéricos.

---

## 3. Modelo de ameaças

Descrever o que se defende — e o que explicitamente não se defende — é parte do trabalho.

### 3.1 Premissas

- A chave é acordada **fora de banda** (pessoalmente, telefone, canal já seguro) entre todos
  os participantes. Ela **nunca trafega** pela rede, nem em texto claro nem cifrada.
- Todos os participantes de uma sessão usam a mesma cifra e a mesma chave (é um esquema de
  chave **simétrica e compartilhada por grupo**).
- O operador do servidor é potencialmente curioso, mas não malicioso a ponto de reescrever
  o servidor. Sob a arquitetura atual, um servidor reescrito **não ganharia nada**: sem a
  chave, ele não decifra.

### 3.2 Adversários considerados e garantias oferecidas

| Adversário | Capacidade | Garantia do sistema |
|---|---|---|
| **A1 — Operador do servidor** | Lê todo o tráfego que passa pelo relay | Vê apenas criptogramas. O servidor não possui a chave e não importa `cifras/` |
| **A2 — Cliente adulterado** | Reescreve `client.py`, escreve bytes arbitrários no socket | Não consegue injetar byte fora de 0–127 em nenhum outro cliente (camada 3 do servidor) |
| **A3 — Cliente falsificador** | Tenta se passar pelo servidor ("Admin: mandem a chave") | Impossível: quadros de tipo `S` vindos de cliente são recusados (§4.3) |
| **A4 — Cliente que fala outro protocolo** | Envia lixo, cabeçalho corrompido, mensagens gigantes | A conexão *dele* cai; as demais seguem intactas (§4.4) |
| **A5 — Observador passivo da rede** | Captura pacotes (`tcpdump`) | Vê criptogramas — a mesma exposição que A1. **A força real depende da cifra escolhida (§6.7)** |

### 3.3 Fora do modelo (não defendido)

- **Confidencialidade forte.** Cifras clássicas caem com criptanálise de papel e lápis (§6.7).
- **Integridade / autenticidade da mensagem.** Não há MAC. Um atacante *ativo* na rede pode
  alterar bytes do criptograma; o destinatário decifrará lixo sem perceber a manipulação.
- **Autenticação de entidade.** Qualquer um que alcance a porta 64146 entra na sala.
- **Sigilo de metadados.** Volume, tamanho e horário das mensagens são visíveis ao relay.
- **Confidencialidade retroativa (*forward secrecy*).** A chave é estática por sessão.

---

## 4. Protocolo de aplicação

### 4.1 O problema: TCP é um fluxo de bytes

TCP não preserva a fronteira entre `send()`s. A implementação ingênua — tratar cada
`recv()` como se fosse exatamente um `send()` — falha nos dois sentidos:

| Patologia | Efeito observado antes da correção |
|---|---|
| **Aglutinação** (*message coalescing*): dois `send()` rápidos chegam num só `recv()` | `"OLA MUNDO"` era exibido como `OLA MUNDO/PXFOPVP:XIFZB…`. Em Playfair, o resultado tende a ter número **ímpar** de letras, o que derrubava o cliente |
| **Fragmentação**: mensagem maior que o buffer chega picada | Cada pedaço era decifrado como se fosse uma mensagem inteira |

### 4.2 A solução: quadro com cabeçalho de tamanho fixo

```
        M 0011 HELLO WORLD
        │  │    └─────────── payload (0 a 9999 bytes ASCII)
        │  └──────────────── tamanho do payload, 4 dígitos DECIMAIS
        └─────────────────── tipo: M = mensagem | S = sistema | C = controle
```

**Gramática formal:**

```
quadro   ::= tipo tamanho payload
tipo     ::= "M" | "S" | "C"
tamanho  ::= DIGITO DIGITO DIGITO DIGITO        ; 0000–9999, zero-padded
payload  ::= <exatamente `tamanho` octetos em [0x00, 0x7F]>
```

Cabeçalho de 5 octetos, `PAYLOAD_MAXIMO = 9999`.

**Decisões justificadas:**

| Decisão | Alternativa rejeitada | Justificativa |
|---|---|---|
| Tamanho em **dígitos decimais** | Inteiro binário (`struct.pack`) | O cabeçalho também trafega. `200` em binário é `0xC8` — um octeto ≥ 0x80 na rede, violando R7. Com dígitos, **o quadro inteiro permanece ASCII** e verificável octeto a octeto |
| **Prefixo de tamanho** | Delimitador `\n` | (i) o delimitador exige a invariante frágil de que nenhum payload contenha `\n`, que vale só enquanto ninguém alterar as cifras; (ii) um payload corrompido levaria junto o resto do fluxo, sem ressincronização possível. Com o tamanho, sabe-se **onde o quadro ruim termina** e pula-se apenas ele |
| **Tipo no cabeçalho** | Inferir pelo conteúdo (`if texto.startswith("SYS:")`) | Ver §4.3 — é uma correção de **segurança**, não de estilo |

### 4.3 O campo de tipo como controle de segurança

Na versão anterior, o receptor adivinhava a natureza da mensagem inspecionando o conteúdo:
`if dado == "/sair"`, `if dado.startswith("SYS:")`. Com o modo **"sem criptografia"**
selecionado, bastava digitar

```
SYS:Admin: mandem a chave no privado
```

para que a mensagem aparecesse nos demais clientes formatada como **aviso oficial do
servidor**. Um ataque de engenharia social viabilizado por um detalhe de parsing.

A correção move a classificação para o cabeçalho e restringe quem pode emiti-lo:

```python
TIPOS_PERMITIDOS_DO_CLIENTE = (TIPO_MENSAGEM, TIPO_CONTROLE)   # "S" está fora
```

No servidor (`tratar_quadro`), um quadro `S` vindo de cliente é registrado e descartado.
O único caminho de emissão de `S` é `broadcast_quadro()`, chamado apenas pelo próprio
servidor. **A falsificação deixa de ser impedida por checagem e passa a ser impossível por
construção.** O teste `teste_cliente_nao_consegue_forjar_aviso_do_servidor` fixa essa
propriedade.

### 4.4 Taxonomia de erros: por que um derruba a conexão e o outro não

A distinção é deliberada e reflete a diferença entre um erro de **enquadramento** e um erro
de **conteúdo**:

| Erro | Exemplo | Ação | Por quê |
|---|---|---|---|
| **Cabeçalho corrompido** → `ErroProtocolo` | tipo `Z`, tamanho `12ab`, octeto alto no cabeçalho | **Encerra a conexão** | Sem um tamanho confiável não se sabe onde o quadro termina, logo não há como pular só ele. O fluxo está perdido; seguir seria interpretar lixo |
| **Payload não-ASCII** → `Quadro.texto is None` | payload com `0xC3` | **Descarta o quadro, conexão segue** | O tamanho já foi lido, então o quadro seguinte continua alinhado. Não há razão para punir a sessão inteira |

### 4.5 O desempacotador

`protocolo.Desempacotador` mantém um `bytearray` acumulador e extrai quadros completos.
**Uma instância por conexão** — compartilhá-la entre clientes embaralharia os fluxos, já
que o buffer é o estado parcial de *um* fluxo específico.

Detalhe de implementação relevante: quando o payload ainda está incompleto, o cabeçalho
**não é consumido**; ele é relido na chamada seguinte, quando o restante chegar. Isso torna
`alimentar()` idempotente do ponto de vista do estado parcial.

```python
d = protocolo.Desempacotador()
for quadro in d.alimentar(sock.recv(1024)):
    ...   # lista vazia = ainda falta byte; é o caso normal, não um erro
```

---

## 5. Política de charset: ASCII estrito

### 5.1 A regra

> Somente octetos no intervalo **0–127** podem circular na rede.

Há uma tensão aparente com a seção 5 do enunciado, que **exige** que as cifras normalizem
`Á → A` e `Ç → C`. A resolução adotada:

1. O texto passa por **normalização Unicode NFD** com descarte das marcas combinantes
   (categoria `Mn`). `Ação → Acao`, `José → Jose`, `ñ → n`.
2. O que **sobrar** fora de 0–127 é **rejeitado**, não convertido: emoji, `€`, `ß`, `æ`,
   cirílico, CJK, `°`, travessão.

A rejeição é uma escolha ética de projeto: substituir silenciosamente por `?` ou remover
sem avisar **alteraria a mensagem do usuário sem que ele soubesse** — pior do que recusá-la.
O usuário recebe o motivo exato e a mensagem não é enviada.

> **Nota sobre a cedilha.** A decomposição NFD já resolve `ç → c + cedilha combinante`, e a
> cedilha combinante é categoria `Mn`. Portanto o `replace("Ç", "C")` manual que existia nos
> quatro módulos de cifra era redundante e foi removido.

### 5.2 Defesa em profundidade: três camadas

Uma única camada não basta, porque **um cliente adulterado pode pular a validação de entrada
e escrever octetos arbitrários direto no socket**.

| Camada | Função | Local | Papel |
|---|---|---|---|
| **1** | `preparar()` / `validar()` | entrada do usuário, antes de cifrar | Ergonomia: informa o usuário e não envia |
| **2** | `codificar()` | saída para a rede | `errors="strict"` — é **impossível** um octeto ≥ 0x80 sair do processo; vira exceção |
| **3** | `decodificar()` | entrada vinda da rede | Verificação octeto a octeto, **antes** de decodificar |

A **camada 3 no servidor é o *choke point***: todo o tráfego passa por ela. Um quadro com
qualquer octeto fora de 0–127 é descartado e não chega a ninguém. É isso — e não a camada 1
— que sustenta o requisito R7 contra o adversário A2.

O critério da camada 3 é **ASCII, não "decodificável"**. UTF-8 bem formado também é
recusado: `"ação"` em UTF-8 são octetos válidos, mas não são ASCII, e o requisito é ASCII.

O cliente **também** valida na recepção, apesar de o servidor já barrar. Verificar dos dois
lados torna a garantia independente de quem está do outro lado da conexão.

### 5.3 Diagnóstico de defeitos que a política eliminou

Os defeitos abaixo foram **reproduzidos por execução**, não inferidos por leitura, e estão
registrados como testes de diagnóstico (`diag_*`) nas suítes de Vigenère e Playfair:

| # | Defeito | Evidência | Situação |
|---|---|---|---|
| 1 | Vigenère corrompia silenciosamente letras fora de A–Z | `привет` → cifra `ekvkwh` → decifra `cdvpsf` ≠ original (**perda silenciosa de dados**) | corrigido |
| 2 | Playfair derrubava o cliente | `ValueError: Letra 'П' não está na matriz`, não capturada | corrigido |
| 3 | Emoji atravessava todas as cifras | `Bom dia 😀` → César → `ERP GLD 😀` saía na rede como UTF-8 | corrigido |
| 4 | "Sem criptografia" era passagem livre | `preço €50` trafegava cru, 100 % não-ASCII | corrigido |
| 5 | Apelido nunca era validado nem cifrado | `José 😀` → `b'Jos\xc3\xa9 \xf0\x9f\x98\x80'` na rede | eliminado (apelidos removidos) |
| 6 | `recv(1024)` cortava caractere multibyte → `UnicodeDecodeError` | mensagem de 1023 chars terminando em emoji derrubava a conexão | **desaparece por consequência**: em ASCII, 1 caractere = 1 octeto |
| 7 | Vigenère estourava `TypeError` com letra que expande no `upper()` | `'ß'.upper() == 'SS'`, e `ord()` recebia string de tamanho 2 | corrigido |
| 8 | `validar_chave` aceitava chave em alfabeto não-ASCII | Vigenère e monoalfabética usavam `isalpha()`, verdadeiro para grego/cirílico | corrigido |

A causa-raiz comum de 1, 2, 7 e 8 é a mesma: **`str.isalpha()` é verdadeiro para qualquer
letra Unicode**. A correção sistemática foi substituí-lo por verificação explícita de
pertinência ao alfabeto que a cifra sabe tratar (`string.ascii_letters` no Vigenère,
a matriz 5×5 no Playfair).

### 5.4 Diagnóstico legível em qualquer console

`descrever_invalidos()` reporta cada ofensor como `U+XXXX`, nunca literalmente:

```python
>>> ascii_puro.descrever_invalidos("preco €50")
'U+20AC'
```

Isso não é preciosismo. O console padrão do Windows é **cp1252**; tentar imprimir um emoji
nele levanta `UnicodeEncodeError` — a mensagem de erro derrubaria o programa que ela
deveria estar explicando.

---

## 6. Catálogo de cifras

### 6.1 O contrato

Todo módulo em `cifras/` implementa exatamente:

```python
validar_chave(chave: str) -> tuple[bool, str]
    # (True, "") se aceitável; (False, "motivo") caso contrário.
    # Cifras sem chave sempre retornam (True, "").

cifrar(texto: str, chave: str) -> str      # texto claro  -> criptograma
decifrar(texto: str, chave: str) -> str    # criptograma  -> texto claro
```

`cifras/registro.py` reúne os módulos num menu numerado. Adicionar uma cifra nova exige
uma entrada em `CIFRAS` e outra em `NOMES` — nada muda em `client.py` ou `server.py`.

### 6.2 Regra comum de normalização

Antes de cifrar, o texto passa por `ascii_puro.normalizar()` (§5.1) e, exceto no Vigenère,
por `.upper()`. **Espaços, dígitos e pontuação são preservados na posição original** — só
as letras são transformadas. O criptograma mantém o "formato" da mensagem original.

Uma decisão sutil e importante: **`decifrar()` não normaliza o texto de novo** (César e
monoalfabética). O argumento recebido já é o criptograma, normalizado quando foi cifrado do
outro lado; reprocessá-lo como se fosse entrada nova é conceitualmente errado. A **chave**,
essa sim, sofre a normalização idêntica à de `cifrar()` — do contrário uma chave acentuada
passaria na validação (que normaliza) e seria usada crua na cifragem.

### 6.3 Opção 1 — Sem criptografia

Função identidade, presente como **baseline de comparação** e como controle experimental:
permite observar no console do servidor a diferença entre ver o texto claro e ver apenas o
criptograma. É o único modo que **não** normaliza o texto.

Note que mesmo aqui a política ASCII (§5) continua valendo — foi justamente com esta opção
que o defeito 4 e o ataque de falsificação de §4.3 eram explorados.

### 6.4 Opção 2 — Cifra de César

Cifra de substituição monoalfabética por deslocamento fixo.

$$C_i = (P_i + k) \bmod 26 \qquad P_i = (C_i - k + 26) \bmod 26$$

- **Chave:** inteiro $k \in [0, 25]$.
- **Espaço de chaves:** $|\mathcal{K}| = 26$ (efetivamente 25; $k=0$ é a identidade)
  — cerca de **4,7 bits**.
- **Implementação:** `decifrar()` reaproveita `cifrar()` com deslocamento negativo. O
  operador `%` do Python devolve resultado não-negativo para divisor positivo, então a
  fórmula funciona sem ajuste.

```
"Ataque ao amanhecer, 05h!"  --(k=3)-->  "DWDTXH DR DPDQKHFHU, 05K!"
```

**Criptanálise:** quebra por **força bruta** em 25 tentativas. É a cifra mais fraca do
conjunto e serve como demonstração de que espaço de chaves pequeno é fatal,
independentemente de qualquer outra propriedade.

### 6.5 Opção 3 — Cifra monoalfabética (substituição geral)

Generalização da César: em vez de um deslocamento, uma **permutação arbitrária** do alfabeto.

$$C_i = \sigma(P_i), \qquad \sigma \in S_{26}$$

- **Chave:** permutação das 26 letras, sem repetição. Ex.: `QWERTYUIOPASDFGHJKLZXCVBNM`.
- **Espaço de chaves:** $26! \approx 4{,}03 \times 10^{26}$ — cerca de **88,4 bits**.
- **Implementação:** `str.maketrans` + `str.translate`; `decifrar()` usa a tabela invertida.
- **Validação:** rejeita chave com comprimento ≠ 26, com letra fora de A–Z (verificação
  explícita contra `ALFABETO`, **não** `isalpha()` — ver §5.3, defeito 8) e com repetições.

```
"Ola mundo"  --(σ = QWERT…)-->  "GSQ DXFRG"
```

**Criptanálise:** apesar do espaço de chaves de 88 bits — comparável a uma chave simétrica
moderna curta — a cifra cai em minutos com **análise de frequência**. É o exemplo canônico
de que *tamanho de chave não é sinônimo de segurança*: a cifra preserva integralmente a
distribuição estatística de primeira ordem do idioma. Em português, `A`, `E` e `O`
concentram ~30 % das letras; digramas (`DE`, `RA`, `ES`) e palavras curtas fecham o resto.

### 6.6 Opção 4 — Cifra de Playfair

Cifra de substituição **digrâmica** (opera sobre pares), publicada por Charles Wheatstone
em 1854 e defendida por Lord Playfair.

**Matriz 5×5** construída com as letras da chave (sem repetição, na ordem de aparição)
seguidas do restante do alfabeto de 25 letras. `J` é fundido em `I`. Com a chave
`PLAYFAIR EXAMPLE`:

```
        P   L  A  Y  F
        I/J R  E  X  M
        B   C  D  G  H
        K   N  O  Q  S
        T   U  V  W  Z
```

**Regras de transformação** de um par $(a, b)$, com `passo = +1` para cifrar e `-1` para
decifrar:

| Caso | Regra |
|---|---|
| Mesma **linha** | Substitui cada letra pela vizinha à direita (cifrar) / esquerda (decifrar), com wraparound `mod 5` |
| Mesma **coluna** | Substitui cada letra pela vizinha abaixo / acima, `mod 5` |
| **Retângulo** | Cada letra é trocada pela que está na sua linha e na coluna da outra. **Esta regra é sua própria inversa** — por isso `_transformar_par` não precisa do sinal de `passo` neste ramo |

**Tratamento de pares — e um refinamento sobre o Playfair ingênuo:**

- Letras iguais no par → insere um *filler* `X` no lugar da segunda.
- **Se a letra duplicada é o próprio `X`**, o filler passa a ser `Q`. Sem isso, `"XX"` forma
  o par `(X, X)`, que as regras de linha e coluna **não separam** — deslocar duas letras
  idênticas devolve duas letras idênticas. O Playfair clássico troca de filler exatamente
  por isso.
- Número ímpar de letras → completa com `X`. O padding final é **sempre `X`, nunca `Q`**, e
  isso importa na decifragem: um `Q` no fim de mensagem é sempre letra real (`IRAQ`), então
  nunca precisa ser adivinhado.

**Remoção heurística dos fillers** (`_remover_x_de_preenchimento`): remove um filler entre
duas letras iguais (`LXL → LL`) e um `X` que sobre como última letra. A conta é feita sobre
a **sequência de letras**, ignorando espaços — a versão anterior comparava vizinhos
imediatos e não reconhecia o filler em `"L L"`, pois o vizinho do `X` era o espaço. A
posição também entra: um filler é sempre a **segunda** letra de um par, logo sempre em
índice ímpar da sequência de letras.

> **Ambiguidade inerente, assumida explicitamente.** Se a mensagem original genuinamente
> tivesse um `X` nessas posições (`"RAIO X"`), ele seria removido por engano. É a mesma
> ambiguidade da decifragem manual de Playfair: o filler só se distingue de uma letra real
> pelo contexto. Documentar isso é mais honesto do que fingir que a heurística é exata.

```
"HELLO WORLD"  --(PLAYFAIR EXAMPLE)-->  "DMYRAN VQCRGE"  -->  "HELLO WORLD"
```

- **Espaço de chaves:** $25! \approx 1{,}55 \times 10^{25}$ (~**83,7 bits**), mas o espaço
  *efetivo* é bem menor, pois chaves derivadas de palavras têm entropia muito abaixo disso.

**Criptanálise:** resiste à análise de frequência de letras isoladas, o que era sua virtude
histórica. Cai, porém, na **análise de frequência de digramas** (676 combinações, ainda
tratável) e sofre de uma fraqueza estrutural notável: a cifra é **recíproca por par no caso
retângulo** e nunca mapeia um digrama para si mesmo. Foi quebrada rotineiramente já na
Primeira Guerra Mundial.

### 6.7 Opção 5 — Cifra de Vigenère

Cifra de substituição **polialfabética**: o deslocamento varia conforme a posição, ditado
por uma palavra-chave repetida ciclicamente.

$$C_i = (P_i + K_{i \bmod m}) \bmod 26 \qquad P_i = (C_i - K_{i \bmod m} + 26) \bmod 26$$

onde $m = |K|$. O `+ 26` na decifragem garante resultado em $[0, 25]$ mesmo com subtração
negativa.

- **Chave:** palavra composta apenas de letras A–Z (após normalização).
- **Espaço de chaves:** $26^m$ para chave de comprimento $m$ — ~4,7 bits por letra.

**Duas particularidades de implementação, ambas deliberadas:**

1. **Caracteres não-alfabéticos não avançam a chave.** Espaços e pontuação são copiados,
   mas `j` só incrementa quando uma letra real é cifrada. Isso significa que o deslocamento
   aplicado à *n*-ésima **letra** independe de quantos espaços a precedem.
2. **A caixa do texto original é preservada** (`base = ord('A') if letra.isupper() else ord('a')`).
   É por isso que `ascii_puro.normalizar()` **não** aplica `.upper()` — Vigenère depende
   disso, e as demais cifras aplicam `.upper()` por conta própria.

```
"Ataque ao amanhecer"  --(LIMAO)-->  "Lbmqip ia aalvteqpz"  -->  "Ataque ao amanhecer"
```

**Robustez defensiva.** `_preparar_chave()` chama `validar_chave()` internamente, porque
`cifrar()`/`decifrar()` **não podem assumir** que foram chamadas após a validação — o chat
valida, mas testes e outros chamadores podem não validar. Sem essa checagem, chave vazia
estourava `ZeroDivisionError` dentro de `j % len(chave)`, um erro que não diz nada sobre a
causa. A **regra** não é duplicada: quem define chave válida continua sendo
`validar_chave()`, para não existirem duas respostas para a mesma pergunta.

**Criptanálise:** conhecida por séculos como *le chiffre indéchiffrable*, foi quebrada por
Babbage (1854, não publicado) e Kasiski (1863). O ataque tem duas fases:

1. **Determinar $m$** — pelo **exame de Kasiski** (distâncias entre repetições de trigramas
   no criptograma tendem a ser múltiplos de $m$) ou pelo **índice de coincidência**, que
   para texto aleatório vale ≈ 0,038 e para texto natural ≈ 0,072–0,078.
2. **Reduzir a $m$ cifras de César** — separadas as posições $i \equiv c \pmod m$, cada
   subsequência é uma César, quebrável por análise de frequência.

O caso $m \geq$ comprimento da mensagem, com chave aleatória e uso único, degenera no
**One-Time Pad** — o único esquema com sigilo perfeito no sentido de Shannon. Nenhuma das
condições é satisfeita neste projeto (chave curta, reutilizada em toda a sessão), o que é
precisamente o que torna a cifra quebrável.

### 6.8 Quadro comparativo

| Cifra | Tipo | $\|\mathcal{K}\|$ | ≈ bits | Ataque decisivo | Custo do ataque |
|---|---|---|---|---|---|
| Sem criptografia | — | 1 | 0 | leitura | trivial |
| César | Substituição mono., deslocamento | 26 | 4,7 | força bruta | 25 tentativas |
| Monoalfabética | Substituição mono., permutação | $26!$ | 88,4 | análise de frequência | minutos, papel e lápis |
| Playfair | Substituição digrâmica | $25!$ | 83,7 | frequência de digramas | horas, texto moderado |
| Vigenère | Substituição polialfabética | $26^m$ | $4{,}7m$ | Kasiski + IC → $m$ Césares | horas, texto ≫ $m$ |

**Conclusão pedagógica do quadro:** monoalfabética e Playfair têm espaço de chaves da ordem
de 84–88 bits — comparável a chaves simétricas reais — e ainda assim são quebráveis
manualmente. **Espaço de chaves grande é condição necessária, jamais suficiente.** O que
falta a todas é *difusão* e *confusão* no sentido de Shannon: nenhuma delas destrói a
estrutura estatística do texto claro.

---

## 7. Concorrência e ciclo de vida das conexões

### 7.1 Modelo de threads

| Processo | Thread | Papel |
|---|---|---|
| **Servidor** | principal | `console_admin()` — lê comandos do operador. **Precisa** ser a principal: só ela recebe sinais do SO (SIGINT) |
| | `receive()` (daemon) | Aceita novas conexões em laço |
| | `handle()` por cliente (daemon) | Recebe e repassa o tráfego de **um** cliente |
| **Cliente** | principal | `write()` — lê `input()`, cifra e envia. Principal pelo mesmo motivo: Ctrl+C |
| | `receive()` (daemon) | Recebe do servidor, remonta quadros e exibe |

Estado compartilhado no servidor (`clients`, `enderecos`) é protegido por
`threading.Lock`. O `broadcast_raw()` copia a lista de destinatários **dentro** do lock e
faz os `send()` **fora** dele, para não serializar a rede sob o lock.

### 7.2 O problema do Ctrl+C em thread secundária

Em CPython, sinais do SO só são entregues à **thread principal**. Mas é a thread secundária
`receive()` do cliente que detecta a queda da conexão — e nesse instante a thread principal
está bloqueada em `input()`, alheia ao fato.

A solução (`encerrar_por_desconexao()`) é a thread secundária disparar um SIGINT para o
próprio processo:

```python
os.kill(os.getpid(), signal.SIGINT)
```

Isso "acorda" a principal e reaproveita o bloco `except KeyboardInterrupt` / `finally` de
cleanup já existente, em vez de duplicar a lógica de encerramento em dois lugares.

### 7.3 Semântica de `/sair`

O mesmo comando tem **dois escopos deliberadamente distintos**:

| Origem | Efeito |
|---|---|
| Digitado no **cliente** | Saída voluntária e **individual**. Envia quadro `C` `/sair`; só aquela conexão cai |
| Digitado no **console do servidor** | `encerrar_tudo()` — **global**: avisa todos com quadro `C`, fecha todos os sockets e o próprio servidor |

Em ambos os caminhos usa-se `shutdown(SHUT_RDWR)` antes de `close()`, para que o FIN do TCP
seja enviado de forma determinística e o `recv()` do outro lado retorne imediatamente, em
vez de depender de timeout do SO.

### 7.4 Separação entre log técnico e mensagem pública

`remover_cliente(motivo=...)` tem dois destinos propositalmente separados:

- o `motivo` técnico (`"saída voluntária (/sair)"`, `"protocolo inválido — …"`,
  `"conexão perdida abruptamente"`) vai **apenas** ao `stdout` do servidor;
- os demais clientes recebem sempre o **mesmo texto fixo e genérico**
  (`"Alguem saiu do chat ;-;"`).

É minimização de vazamento de informação: o usuário do chat não precisa saber *como*
alguém saiu, e o endereço IP nunca é divulgado.

---

## 8. Execução

### 8.1 Requisitos

- **Python 3.9+** (desenvolvido e testado em **3.12.10**).
- **Nenhuma dependência externa** — apenas a biblioteca padrão.

### 8.2 Passos

Abra **um terminal para o servidor** e **um por participante**, todos na raiz do projeto.

**1 — Servidor:**

```bash
python server.py
```

```
Servidor está online... (digite /sair para encerrar tudo)
Modo ASCII: quadros com qualquer byte fora de 0-127 são descartados.
```

**2 — Cada cliente:**

```bash
python client.py
```

```
Chat em modo ASCII: acentos são convertidos, o resto não é aceito.

Combine com os outros participantes, por fora da rede, a mesma cifra e chave.
Escolha o modo de transmissão:
1 - Sem criptografia
2 - Cifra de César
3 - Cifra monoalfabética
4 - Cifra de Playfair
5 - Cifra de Vigenère
Opção: 2
Chave: 3
 >
```

> **Todos os participantes devem escolher a MESMA cifra e a MESMA chave.** A escolha é
> 100 % local: nada dela trafega pela rede. Se um cliente usar chave diferente, ele exibirá
> lixo — e, por projeto, **isso não derruba ninguém** (ver §6.6, `decifrar()` do Playfair).

### 8.3 Configuração de rede

`host = "127.0.0.1"`, `port = 64146`, definidos no topo de `server.py` e no `connect()` de
`client.py`. Para uso em rede local, altere o `bind` do servidor para `"0.0.0.0"` e aponte o
cliente ao IP da máquina servidora.

### 8.4 Sessão de exemplo (César, k=3)

| Onde | O que aparece |
|---|---|
| Cliente A digita | `Ataque ao amanhecer, 05h!` |
| Na rede (octetos) | `M0025DWDTXH DR DPDQKHFHU, 05K!` |
| Console do servidor | `[CIFRADO recebido] DWDTXH DR DPDQKHFHU, 05K!` |
| Cliente B vê | `[CIFRADO]   DWDTXH DR DPDQKHFHU, 05K!`<br>`[DECIFRADO] ATAQUE AO AMANHECER, 05H!` |

O servidor exibir o criptograma no seu próprio log é intencional: é a **demonstração
empírica** de que ele não tem acesso ao conteúdo (R3).

### 8.5 Casos de teste manual sugeridos para a apresentação

| Entrada | Resultado esperado |
|---|---|
| `Ação, é hoje!` | Enviada como `ACAO, E HOJE!` (acentos normalizados) |
| `preço €50` | **Não enviada.** `Mensagem não enviada — só é permitido ASCII. Removido: caractere não-ASCII: U+20AC` |
| `Bom dia 😀` | **Não enviada** (`U+1F600`) |
| Modo 1 + `SYS:Admin: mandem a chave` | Chega como **mensagem comum**, não como aviso do servidor (§4.3) |
| Duas mensagens em sequência muito rápida | Chegam **separadas**, nunca aglutinadas (§4.2) |

---

## 9. Verificação e testes

### 9.1 Estratégia

A verificação é feita em três níveis, sem dependências externas (nenhum `pytest`): cada
arquivo é um programa executável com seu próprio *runner*, que imprime `[OK]`/`[FALHA]` por
teste e sai com código ≠ 0 se algo falhar.

| Nível | Arquivos | O que cobre |
|---|---|---|
| **Unitário** | `test_ascii_puro`, `test_protocolo`, `test_cesar`, `test_monoalfabetica`, `test_playfair`, `test_vigenere` | Contratos, casos-limite, validação de chave |
| **Propriedade** | dentro dos anteriores | Ida-e-volta exaustiva: **todas** as 26 chaves de César, todo o alfabeto na monoalfabética, os **128** caracteres ASCII no protocolo |
| **Integração** | `test_integracao_ascii` | Sobe o `server.py` **real** em subprocesso e conversa por **sockets crus** |
| **Doctest** | módulos de produção | Exemplos da documentação são executáveis e verificados |

**Por que sockets crus na integração.** O `client.py` valida a entrada (camada 1), mas o
requisito é que nada não-ASCII trafegue **mesmo com um cliente adulterado** — e um cliente
adulterado é exatamente isto: alguém escrevendo octetos arbitrários direto no socket. Usar
o `client.py` no teste seria testar justamente a camada fácil de contornar.

### 9.2 Como rodar

```bash
# a partir da raiz do projeto
python tests/test_ascii_puro.py
python tests/test_protocolo.py
python tests/test_cesar.py
python tests/test_monoalfabetica.py
python tests/test_playfair.py
python tests/test_vigenere.py
python tests/test_integracao_ascii.py     # sobe o servidor real; leva alguns segundos

# doctests dos módulos de produção (sem saída = tudo passou)
python -m doctest ascii_puro.py protocolo.py cifras/cesar.py cifras/monoalfabetica.py cifras/playfair.py cifras/vigenere.py
```

> O teste de integração ocupa a porta **64146**. Encerre qualquer `server.py` em execução
> antes de rodá-lo.

### 9.3 Resultado da execução corrente

| Suíte | Testes | Situação |
|---|---:|---|
| `test_ascii_puro.py` | 30/30 | ✅ |
| `test_protocolo.py` | 27/27 | ✅ |
| `test_cesar.py` | 13/13 | ✅ |
| `test_monoalfabetica.py` | 14/14 | ✅ |
| `test_playfair.py` | 33/33 | ✅ |
| `test_vigenere.py` | 17/17 | ✅ |
| `test_integracao_ascii.py` | 13/13 | ✅ |
| **Total** | **147/147** | ✅ |
| Doctests (6 módulos) | — | ✅ sem falhas |
| Diagnósticos `diag_*` (Playfair + Vigenère) | 0/9 defeitos ainda presentes | ✅ |

Os testes `diag_*` são um recurso metodológico: cada um **reproduz** um defeito da §5.3 e
reporta se ele ainda existe. Servem como registro auditável de que o defeito era real e de
que a correção o eliminou.

### 9.4 Propriedades de segurança fixadas por teste

| Teste | Propriedade garantida |
|---|---|
| `teste_servidor_nao_repassa_payload_nao_ascii` | R7 vale contra o adversário A2 |
| `teste_byte_alto_no_payload_e_sempre_bloqueado` | Idem, varrendo o intervalo 0x80–0xFF |
| `teste_quadro_bloqueado_nao_derruba_a_conexao` | Erro de conteúdo ≠ erro de enquadramento (§4.4) |
| `teste_cliente_nao_consegue_forjar_aviso_do_servidor` | Anti-falsificação de quadro `S` (§4.3, A3) |
| `teste_texto_comecando_com_sys_e_apenas_uma_mensagem_comum` | Ausência de regressão para inferência por conteúdo |
| `teste_cabecalho_corrompido_derruba_so_o_infrator` | Isolamento de falhas entre conexões (A4) |
| `teste_duas_mensagens_em_um_unico_send_chegam_separadas` | Correção da aglutinação |
| `teste_mensagem_picada_em_varios_envios_e_remontada` | Correção da fragmentação |
| `teste_mensagem_maior_que_o_buffer_de_recv` | Idem, acima de 1024 octetos |
| `teste_nao_existe_handshake_de_apelido` | Anonimato (§2.2d) |
| `teste_avisos_de_sistema_sao_anonimos_e_ascii` | Não vazamento de endereço |

---

## 10. Limitações conhecidas

Enumeradas como parte do trabalho, não omitidas.

**Criptográficas**

1. **Nenhuma cifra implementada é segura** contra criptanálise moderna (§6.8). O objetivo é
   didático.
2. **Sem integridade nem autenticidade.** Não há MAC. Um atacante ativo pode alterar o
   criptograma em trânsito; o receptor decifra lixo sem detectar a manipulação.
3. **Sem distribuição de chave.** A chave é combinada fora de banda — o que é *correto*
   dado o modelo (§3.1), mas não escala e não oferece *forward secrecy*.
4. **Chave estática por sessão.** Toda a conversa usa o mesmo material de chave, o que é
   exatamente a condição que viabiliza os ataques Kasiski/IC no Vigenère.
5. **Ambiguidade de filler no Playfair** (§6.6): mensagens que legitimamente contenham `X`
   nas posições de padding perdem esse caractere.

**Arquiteturais**

6. **Uma thread por cliente.** Modelo simples e adequado à escala do trabalho, mas
   $O(n)$ em threads. Para muitas conexões, o caminho seria `selectors`/`asyncio`.
7. **Sem persistência.** Nenhuma mensagem é armazenada; o histórico não sobrevive à sessão.
8. **Sem autenticação de entidade.** Qualquer um que alcance a porta entra na sala.
9. **Payload limitado a 9999 octetos** por quadro (§4.2). Suficiente para chat digitado, mas
   é um limite duro do formato.
10. **Sem TLS.** Adicioná-lo daria confidencialidade e integridade **contra a rede**, mas
    não contra o servidor — que continuaria sendo o ponto de terminação. A propriedade de
    servidor cego deste projeto é ortogonal a isso e, nesse aspecto específico, mais forte.

**Extensões naturais** (fora do escopo entregue): cifra de fluxo RC4 (nome da branch de
desenvolvimento) ou XOR, o que exigiria codificação de transporte (Base64 ou hexadecimal)
para manter a saída dentro de ASCII, já que essas cifras produzem octetos arbitrários —
uma consequência direta e interessante da restrição R7.

---

## 11. Estrutura de arquivos

```
chat-tcp-criptografado/
│
├── server.py                  Relay TCP multithread. Não importa cifras/ — por projeto.
├── client.py                  Interface do usuário, seleção de cifra, envio e recepção.
│
├── ascii_puro.py              Ponto único de verdade sobre charset. 3 camadas de defesa.
├── protocolo.py               Enquadramento tipo+tamanho+payload. Desempacotador por conexão.
│
├── cifras/
│   ├── __init__.py
│   ├── registro.py            Menu numerado. Único lugar a tocar para adicionar cifra.
│   ├── sem_criptografia.py    Identidade + documentação do CONTRATO das cifras.
│   ├── cesar.py               Substituição monoalfabética por deslocamento.
│   ├── monoalfabetica.py      Substituição por permutação (str.maketrans).
│   ├── playfair.py            Substituição digrâmica, matriz 5×5, fillers X/Q.
│   └── vigenere.py            Substituição polialfabética, preserva caixa.
│
├── tests/
│   ├── test_ascii_puro.py         30 testes — política de charset
│   ├── test_protocolo.py          27 testes — enquadramento e erros
│   ├── test_cesar.py              13 testes — inclui varredura das 26 chaves
│   ├── test_monoalfabetica.py     14 testes
│   ├── test_playfair.py           33 testes + 5 diagnósticos
│   ├── test_vigenere.py           17 testes + 4 diagnósticos
│   └── test_integracao_ascii.py   13 testes — servidor real, sockets crus
│
├── docs/
│   └── superpowers/specs/
│       └── 2026-08-28-chat-ascii-only-design.md   Documento de projeto: diagnóstico
│                                                   dos defeitos e decisões de arquitetura
│
├── README-VIGENERE-PLAYFAIR.md   Documento de apoio à apresentação: passo a passo
│                                  didático das duas cifras
└── README.md                     Este documento
```

**Convenção de documentação adotada:** os *docstrings* dos módulos deste projeto explicam
**por que** cada decisão foi tomada, incluindo as alternativas rejeitadas e os defeitos
concretos que motivaram cada correção. Isso é intencional — em um trabalho de segurança, o
raciocínio é tão avaliável quanto o código. Vários exemplos nesses docstrings são
**doctests executáveis**, o que impede que a documentação divirja silenciosamente da
implementação.

---

## 12. Referências

**Cifras clássicas e criptanálise**

- SINGH, Simon. *The Code Book: The Science of Secrecy from Ancient Egypt to Quantum
  Cryptography*. Anchor Books, 1999. — exame de Kasiski, história do Vigenère e do Playfair.
- STINSON, Douglas R.; PATERSON, Maura B. *Cryptography: Theory and Practice*. 4. ed. CRC
  Press, 2018. — formalização das cifras de substituição, índice de coincidência.
- STALLINGS, William. *Cryptography and Network Security: Principles and Practice*. 8. ed.
  Pearson, 2020. — cap. 3: César, monoalfabética, Playfair, Vigenère e seus ataques.
- KAHN, David. *The Codebreakers*. Scribner, 1996.
- SHANNON, Claude E. *Communication Theory of Secrecy Systems*. Bell System Technical
  Journal, v. 28, n. 4, p. 656–715, 1949. — sigilo perfeito, confusão e difusão.
- KASISKI, Friedrich W. *Die Geheimschriften und die Dechiffrir-Kunst*. Berlim, 1863.

**Normas e especificações**

- IETF. **RFC 20** — *ASCII format for Network Interchange*, 1969.
- IETF. **RFC 793 / RFC 9293** — *Transmission Control Protocol*. — TCP como fluxo de
  octetos sem preservação de fronteiras de mensagem.
- UNICODE CONSORTIUM. **UAX #15** — *Unicode Normalization Forms*. — formas NFD/NFC e a
  categoria `Mn` (*Mark, nonspacing*) usada em `ascii_puro.normalizar()`.

**Documentação técnica**

- PYTHON SOFTWARE FOUNDATION. `socket`, `threading`, `unicodedata`, `doctest` —
  <https://docs.python.org/3/library/>
- STEVENS, W. Richard; FENNER, Bill; RUDOFF, Andrew M. *UNIX Network Programming, Volume 1:
  The Sockets Networking API*. 3. ed. Addison-Wesley, 2003. — enquadramento de mensagens
  sobre fluxos de octetos.

---

<sub>Trabalho acadêmico — disciplina de Cibersegurança. As cifras aqui implementadas têm
finalidade exclusivamente didática e **não devem ser usadas para proteger informação real**.</sub>
