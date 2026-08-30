# Cifras de Vigenère e Playfair — explicação do código

Documento de apoio para apresentação. Explica **o que cada cifra faz**, **como o código
foi organizado** e **por que cada decisão foi tomada**.

Arquivos comentados aqui:

- `cifras/vigenere.py`
- `cifras/playfair.py`

As duas cifras seguem o mesmo "contrato" das outras do projeto (César e monoalfabética),
para que o chat possa trocar de cifra sem mudar nada no `client.py` / `server.py`:

| Função | Para que serve |
|---|---|
| `validar_chave(chave)` | Diz se a chave digitada pelo usuário serve. Responde `(True, "")` ou `(False, "motivo do erro")`. |
| `cifrar(texto, chave)` | Recebe a mensagem original e devolve a mensagem embaralhada. |
| `decifrar(texto, chave)` | Recebe a mensagem embaralhada e devolve a original. |

O arquivo `cifras/registro.py` só junta todas as cifras em um "cardápio" numerado
(1 = sem criptografia, 2 = César, 3 = monoalfabética, **4 = Playfair**, **5 = Vigenère**).

---

## Regra comum às duas: só letras são cifradas

Antes de cifrar, o texto passa por uma **normalização**:

- acentos são removidos → `Ã` vira `A`, `ç` vira `c`, `É` vira `E`;
- espaços, números e pontuação **não são alterados** e continuam **na mesma posição**.

Por que isso importa? Porque as duas cifras trabalham em cima de um alfabeto fixo
(26 letras no Vigenère, 25 no Playfair). Um "ã" ou uma vírgula não têm posição nesse
alfabeto. Removendo o acento, a letra continua existindo; mantendo a pontuação intacta,
a mensagem cifrada continua com o mesmo "formato" da original (mesmos espaços, mesma
pontuação), o que facilita a leitura no chat.

> Detalhe técnico (só se o professor perguntar): a remoção de acento usa a biblioteca
> `unicodedata`. Ela separa "ã" em duas partes — a letra "a" e o sinal "~" — e depois
> joga fora o sinal, sobrando só a letra base.

A implementação dessa normalização mora em `ascii_puro.normalizar()`, um módulo só dela,
compartilhado por todas as cifras — antes eram quatro cópias quase idênticas espalhadas.

## Só letras A–Z ASCII, e por quê

O chat trafega **exclusivamente ASCII** (0–127). Isso muda uma coisa importante nas duas
cifras: onde antes o código perguntava `letra.isalpha()`, hoje ele verifica
explicitamente se a letra está entre A–Z.

A diferença parece pequena, mas `isalpha()` responde **verdadeiro para qualquer letra
Unicode** — grego, cirílico, `ß`. E aí a conta quebrava:

- `Ω` entrava no cálculo como se fosse letra latina, o `% 26` destruía o valor, e o texto
  decifrado nunca voltava ao original (perda silenciosa de dados);
- `ß`.upper() devolve `SS` — **dois** caracteres — e `ord()` estourava `TypeError`,
  derrubando o cliente;
- no Playfair, `П` chegava em `_localizar()` e levantava `ValueError`, também derrubando
  o cliente.

Restringindo a A–Z, essas letras passam a ser tratadas como pontuação: não são cifradas,
mas também não corrompem nada nem quebram o programa.

---

# 1. Cifra de Vigenère (`cifras/vigenere.py`)

## A ideia

É uma **cifra de César com deslocamento variável**. Na César, todas as letras andam a
mesma quantidade de casas no alfabeto. No Vigenère, **cada letra anda uma quantidade
diferente**, definida por uma palavra-chave que se repete ao longo da mensagem.

Cada letra vira um número: `A=0, B=1, C=2, ..., Z=25`.

```
Cifrar:   C = (P + K) mod 26
Decifrar: P = (C - K + 26) mod 26
```

- `P` = número da letra do texto original
- `K` = número da letra da chave naquela posição
- `C` = número da letra cifrada
- `mod 26` = "dá a volta no alfabeto", como um relógio: depois do Z volta pro A

## Exemplo completo

Mensagem: `ATACAR AO` — Chave: `LIMAO`

| Texto  | A | T | A | C | A | R | (espaço) | A | O |
|---|---|---|---|---|---|---|---|---|---|
| Chave  | L | I | M | A | O | L | — | I | M |
| P      | 0 | 19| 0 | 2 | 0 | 17| — | 0 | 14|
| K      | 11| 8 | 12| 0 | 14| 11| — | 8 | 12|
| P+K    | 11| 27| 12| 2 | 14| 28| — | 8 | 26|
| mod 26 | 11| 1 | 12| 2 | 14| 2 | — | 8 | 0 |
| **Cifrado** | **L** | **B** | **M** | **C** | **O** | **C** | (espaço) | **I** | **A** |

Resultado: `ATACAR AO AMANHECER` com a chave `LIMAO` vira **`LBMCOC IA AALVTEQPZ`**.

Repare no espaço: ele foi copiado, e a chave **não avançou** nele. A 7ª letra do texto
(`A`, de "AO") usa a 7ª letra da chave (`I`), não a 8ª. Essa é a decisão de projeto mais
importante do arquivo.

## Como o código faz isso

```python
resultado = []
j = 0                       # posição atual DENTRO DA CHAVE

for letra in texto:
    if not _eh_letra_ascii(letra):  # espaço, vírgula, número, letra de outro alfabeto
        resultado.append(letra)     # copia igual
        continue                    # e NÃO mexe no j (chave não avança)

    base = ord('A') if letra.isupper() else ord('a')   # guarda a caixa (maiúscula/minúscula)

    P = ord(letra.upper()) - ord('A')      # letra -> número
    K = ord(chave[j % len(chave)]) - ord('A')  # letra da chave -> número
    C = (P + K) % 26                       # a fórmula

    resultado.append(chr(C + base))        # número -> letra, na caixa original
    j += 1                                 # só agora a chave avança
```

Três pontos para explicar na apresentação:

1. **`j` é o contador da chave, separado do contador do texto.** Ele só cresce quando uma
   letra de verdade foi cifrada. É isso que faz espaços e pontuação "não gastarem" letra
   da chave.
2. **`j % len(chave)`** é o que faz a chave se repetir em ciclo. Se a chave tem 5 letras,
   quando `j` chega a 5 o resto da divisão volta a 0 e a chave recomeça do início.
   Por isso `LIMAO` vira `LIMAOLIMAOLIMAO...` automaticamente, sem precisar montar essa
   string repetida na memória.
3. **`base`** guarda se a letra era maiúscula ou minúscula, para devolver o resultado no
   mesmo padrão. `ord()` converte letra em número; `chr()` faz o caminho de volta.

## Decifrar

É exatamente o mesmo código, trocando `+ K` por `- K`. O único cuidado extra é o `+ 26`:

```python
P = (C - K + 26) % 26
```

Sem ele, uma subtração poderia dar negativo (ex.: `2 - 10 = -8`) e cair fora do intervalo
de 0 a 25. Somar 26 antes da divisão garante que o número fique sempre válido — é o mesmo
"dar a volta no relógio", só que para trás.

## Validação da chave

A chave precisa ser **não vazia** e, depois de tirados os acentos, conter **apenas letras
de A a Z**. Números, símbolos e espaços são rejeitados porque não existe "deslocamento"
para o caractere `#`, `7` ou ` ` — a fórmula só funciona com letras do alfabeto. Letras de
outros alfabetos (grego, cirílico) também são rejeitadas, pelo mesmo motivo: não há como
convertê-las em um número de 0 a 25.

`cháve` é aceita e vale exatamente o mesmo que `chave` — a validação normaliza antes de
julgar, que é o mesmo tratamento que `cifrar()` dá ao texto.

**As funções se defendem sozinhas.** `cifrar()` e `decifrar()` chamam a validação por
dentro, em vez de confiar que quem chamou já validou. Antes, chamar `cifrar("ATAQUE", "")`
direto estourava `ZeroDivisionError` lá no meio da conta (`j % len(chave)`) — um erro que
não diz nada sobre a causa. Hoje levanta `ValueError: A chave não pode ser vazia.`

## Ponto de segurança (o que o professor provavelmente vai perguntar)

Vigenère é muito mais forte que César porque a mesma letra do texto pode virar letras
diferentes no cifrado (veja o `A` do exemplo virando `L`, `M`, `O`, `A`...). Isso quebra a
análise de frequência simples. Mas **ainda é quebrável**: se a chave for curta e a
mensagem longa, dá para descobrir o tamanho da chave (teste de Kasiski / índice de
coincidência) e a partir daí quebrar cada posição como uma César comum.

---

# 2. Cifra de Playfair (`cifras/playfair.py`)

## A ideia

Playfair não cifra letra por letra: cifra **de duas em duas**. Isso é o que a torna mais
forte que as anteriores — a frequência das letras individuais deixa de entregar o texto.

O funcionamento tem 3 etapas:

### Etapa 1 — Montar a matriz 5×5

A chave preenche um quadrado de 5×5 = **25 casas**. Como o alfabeto tem 26 letras, o
**J é tratado como I** (os dois dividem a mesma casa). É a convenção clássica da cifra.

Regra: escreve-se a chave, **descartando letras repetidas**, e depois completa-se com o
resto do alfabeto na ordem.

Com a chave `SEGURANCA`:

- letras da chave sem repetição → `S E G U R A N C` (o segundo `A` é descartado)
- completa com o resto do alfabeto → `B D F H I K L M O P Q T V W X Y Z`

```
      col 0 1 2 3 4
lin 0    S E G U R
lin 1    A N C B D
lin 2    F H I K L      ← I e J na mesma casa
lin 3    M O P Q T
lin 4    V W X Y Z
```

No código isso é `_montar_matriz()`, que devolve a matriz como uma lista de 5 palavras de
5 letras: `['SEGUR', 'ANCBD', 'FHIKL', 'MOPQT', 'VWXYZ']`. A busca da posição de uma
letra (`_localizar`) devolve `(linha, coluna)`.

### Etapa 2 — Separar a mensagem em pares

Regras clássicas, implementadas em `_montar_pares()`:

- **letras iguais no mesmo par** → insere um `X` no lugar da segunda.
  `HELLO` → `HE LX LO` (o par `LL` não pode existir);
- **a letra duplicada é o próprio `X`** → o preenchimento vira `Q`.
  `XX` → `XQ X…`, nunca `XX`;
- **sobrou uma letra no final** (número ímpar de letras) → completa com `X`.

A segunda regra é a que costuma ser esquecida, e o motivo é bonito: separar `XX` com um
`X` produziria o par `(X, X)`. Mas as regras de linha e de coluna deslocam as duas letras
do par na mesma direção — duas letras **idênticas** entram e duas letras idênticas saem.
O par nunca seria realmente separado, e na hora de decifrar a limpeza comeria as duas.
Trocar o filler por `Q` resolve. O Playfair clássico faz exatamente isso.

O preenchimento **final** (o de número ímpar) continua sendo sempre `X`, nunca `Q`. Isso
não é detalhe: é o que permite decifrar `IRAQ` sem perder o `Q` — se `Q` também pudesse
ser padding de fim de mensagem, não haveria como distinguir.

### Etapa 3 — Transformar cada par

Só existem 3 casos (`_transformar_par()`):

| Caso | Regra para cifrar | Exemplo (matriz acima) |
|---|---|---|
| **Mesma linha** | cada letra anda **uma casa para a direita** (do fim volta pro começo) | `AC` → `NB` |
| **Mesma coluna** | cada letra anda **uma casa para baixo** (do fim volta pro topo) | `AM` → `FV` |
| **Retângulo** (linhas e colunas diferentes) | cada letra é trocada pela letra da **sua linha, na coluna da outra** | `AT` → `DM` |

Para decifrar é a mesma coisa ao contrário: anda para a **esquerda** e para **cima**.
O caso do retângulo é idêntico nos dois sentidos — ele é o inverso de si mesmo.

No código isso é um único parâmetro chamado `passo`, que vale `1` para cifrar e `-1` para
decifrar:

```python
if la == lb:   # mesma linha  -> mexe na coluna
    return matriz[la][(ca + passo) % 5], matriz[lb][(cb + passo) % 5]
if ca == cb:   # mesma coluna -> mexe na linha
    return matriz[(la + passo) % 5][ca], matriz[(lb + passo) % 5][cb]
return matriz[la][cb], matriz[lb][ca]   # retângulo (igual nos dois sentidos)
```

O `% 5` faz o mesmo papel do `mod 26` do Vigenère: se passar da borda da matriz, dá a
volta para o outro lado.

## Exemplo completo

Mensagem: `ATACAR AO AMANHECER` — Chave: `SEGURANCA`

Letras extraídas (17, número ímpar) e agrupadas em pares:

```
AT  AC  AR  AO  AM  AN  HE  CE  R+X
```

| Par | Caso | Vira |
|---|---|---|
| A T | retângulo | D M |
| A C | mesma linha | N B |
| A R | retângulo | D S |
| A O | retângulo | N M |
| A M | mesma coluna | F V |
| A N | mesma linha | N C |
| H E | mesma coluna | O N |
| C E | retângulo | N G |
| R X | retângulo (X é preenchimento) | G Z |

Resultado: **`DMNBDS NM FVNCONNGGZ`** — e `decifrar()` devolve `ATACAR AO AMANHECER`.

## A parte mais delicada do código: reencaixar as letras no texto

Aqui está a diferença entre este código e um Playfair "de livro". No livro, a saída é um
bloco de letras coladas (`DMNBDSNMFVNCONNGGZ`). Aqui, como é um **chat**, a mensagem
precisa sair com os espaços e a pontuação nos lugares originais.

O problema: Playfair **cria letras a mais** (os `X` de preenchimento). Então o texto
cifrado pode ter mais letras que o original, e não dá para simplesmente trocar letra por
letra.

A solução no `cifrar()`:

1. cada par cifrado é guardado junto de uma marca dizendo se aquela letra é **real**
   (veio do texto) ou é um **`X` de preenchimento**;
2. ao remontar a mensagem, percorre-se o texto original: se for espaço/pontuação, copia;
   se for letra, pega a próxima letra cifrada real **e também qualquer `X` de
   preenchimento que venha logo em seguida**, colando-o junto da letra que o originou;
3. se sobrar um `X` do último par (mensagem com número ímpar de letras), ele é colocado
   no fim.

No exemplo acima, o `GZ` final (que veio do `R` + `X` de preenchimento) aparece grudado no
fim da última palavra — por isso `AMANHECER` (9 letras) virou `FVNCONNGGZ` (10 letras).

## Ao decifrar: como saber quais X eram preenchimento?

Não dá para saber com certeza absoluta — e isso é honesto admitir na apresentação. A
função `_remover_x_de_preenchimento()` faz uma limpeza **heurística**, com duas regras:

- um filler (`X` ou `Q`) entre **duas letras iguais** foi inserido pela regra do par
  duplicado → `HELXLO` volta a ser `HELLO`;
- um `X` **na última letra** da mensagem foi o preenchimento de texto ímpar → é removido.
  (Só `X`. Um `Q` no fim é sempre letra de verdade, pela regra explicada acima.)

Dois detalhes de implementação que valem a pena saber, porque são onde estavam os bugs:

1. **A conta é feita sobre a sequência de LETRAS, não de caracteres.** A versão anterior
   olhava o caractere imediatamente vizinho, e por isso não reconhecia o filler em `L L`:
   o vizinho do `X` era o **espaço**, não o `L` que o originou. Resultado: `L L` voltava
   como `LX L`. Hoje espaços e pontuação são pulados na comparação.
2. **A posição entra na conta.** Um filler é sempre a *segunda* letra de um par, logo
   está sempre em índice ímpar da sequência de letras. Verificar isso evita remover uma
   letra real que por acaso caia entre duas iguais.

**Limitação assumida (essa continua):** se a mensagem tiver um número **par** de letras e
terminar genuinamente em `X` (ex.: `OX`), esse `X` é removido por engano. Note que
`RAIO X` funciona — tem 5 letras, número ímpar, então o `X` do texto é seguido de um `X`
de padding, e só o padding sai. A ambiguidade **não é um bug do código, é da própria
cifra Playfair**: quem decifra Playfair no papel também precisa olhar o contexto para
decidir se um `X` é do texto ou é enchimento.

## Decifrar não pode derrubar o programa

`decifrar()` normaliza a entrada exatamente como `cifrar()` faz, e trata número ímpar de
letras passando a letra órfã adiante sem transformá-la.

Isso não é preciosismo. No chat, o texto chega **da rede**: se o outro participante
escolheu outra cifra por engano, o que chega aqui não saiu deste `cifrar()`. Antes,
minúscula levantava `ValueError` dentro de `_localizar()` e número ímpar de letras
levantava `StopIteration` — e as duas **derrubavam o cliente inteiro**, porque a thread de
recepção não sobrevive a uma exceção. Decifrar lixo tem que produzir lixo, não uma queda.

## Validação da chave

Menos rígida que a do Vigenère: basta a chave conter **pelo menos uma letra**. Números e
símbolos até podem ser digitados, mas são simplesmente ignorados na hora de montar a
matriz — diferente do Vigenère, onde cada letra da chave vira um deslocamento numérico e
um caractere inválido quebraria a fórmula.

## Ponto de segurança

Playfair cifra **pares (digramas)**, então a análise de frequência de letras isoladas não
funciona. Além disso, a mesma letra pode virar coisas diferentes dependendo do par em que
cai (veja o `A` do exemplo virando `D`, `N`, `D`, `N`, `F`, `N`). Mesmo assim é uma cifra
clássica: com texto suficiente, dá para fazer análise de frequência de **digramas**
(`TH`, `ER`, `QU`... em inglês/português) e quebrá-la. Foi usada de verdade pelo exército
britânico na 1ª e 2ª Guerra Mundial justamente por ser forte o bastante para o campo de
batalha e simples o bastante para ser feita à mão.

---

# Comparação rápida das duas

| | Vigenère | Playfair |
|---|---|---|
| Unidade cifrada | 1 letra por vez | 2 letras por vez (par) |
| Alfabeto | 26 letras | 25 letras (J vira I) |
| Estrutura da chave | palavra que se repete em ciclo | palavra que preenche uma matriz 5×5 |
| Operação | soma/subtração com `mod 26` | posição na matriz (linha/coluna/retângulo) |
| Tamanho da saída | igual ao da entrada | pode ser **maior** (X de preenchimento) |
| Reversível 100%? | Sim | Quase — os `X` de preenchimento são ambíguos |
| Ataque conhecido | Kasiski / índice de coincidência | frequência de digramas |

---

# Casos-limite: o que já foi corrigido e o que sobra

Os dois arquivos de teste terminam com uma seção de **diagnóstico de casos-limite**. Cada
defeito foi primeiro escrito ali como um teste que falhava, e só depois corrigido — então
a suíte hoje mostra `0/4` e `0/5` defeitos presentes. Vale conhecer a lista, porque é
exatamente o tipo de coisa que o professor pode perguntar.

**Já corrigido no Vigenère**
- Chave vazia estourava `ZeroDivisionError` dentro de `cifrar()`. Hoje `cifrar()` valida a
  chave por dentro e levanta um `ValueError` que explica o problema.
- `ß` derrubava o cliente com `TypeError`, porque `'ß'.upper()` devolve **dois**
  caracteres e `ord()` não aceita isso.
- Letras fora de A–Z (grego, cirílico) eram aceitas e **corrompiam o texto em silêncio** —
  o decifrado nunca voltava ao original.
- `validar_chave()` aceitava chave em alfabeto não suportado.

**Já corrigido no Playfair**
- `decifrar()` estourava `ValueError` com entrada minúscula e `StopIteration` com número
  ímpar de letras — as duas derrubavam o cliente do chat.
- `L L` (letras duplicadas separadas por espaço) voltava como `LX L`.
- `XX` voltava como `X`, porque o par `(X, X)` nunca era separado de verdade.
- `ŉ` derrubava o cliente com `ValueError` (`'ŉ'.upper()` == `'ʼN'`, e o modificador `ʼ`
  passava no `isalpha()`).

**O que continua valendo como limitação, por decisão**
- **Perda intencional:** todo `J` vira `I` e não volta. Não é bug — é a definição da
  cifra, que só tem 25 casas na matriz.
- **Ambiguidade do `X` final:** uma mensagem com número par de letras terminando em `X`
  (`OX`) perde esse `X` ao decifrar. É ambiguidade da própria cifra, não do código —
  explicada em detalhe na seção acima.
- Playfair **muda o tamanho** da mensagem (os fillers), então o texto cifrado pode ter
  mais letras que o original.

---

# Como testar / demonstrar

Testes automatizados isolados (não sobem o chat, não usam rede):

```
python tests/test_vigenere.py     # 17/17 testes, 0/4 defeitos presentes
python tests/test_playfair.py     # 33/33 testes, 0/5 defeitos presentes
```

Cada suíte imprime primeiro os testes normais e depois a seção de **diagnóstico**, com os
casos-limite listados mais abaixo neste documento. Um `0/N defeitos ainda presentes` no
fim é o que se espera hoje.

Teste rápido no terminal, a partir da raiz do projeto:

```
python -c "from cifras import vigenere; print(vigenere.cifrar('ATACAR AO AMANHECER', 'LIMAO'))"
python -c "from cifras import playfair; print(playfair.cifrar('ATACAR AO AMANHECER', 'SEGURANCA'))"
```

No chat, as cifras aparecem no menu como opção **4 (Playfair)** e **5 (Vigenère)**.
