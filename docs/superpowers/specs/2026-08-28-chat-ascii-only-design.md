# Chat TCP: comunicação exclusivamente ASCII e remoção de apelidos

Data: 2026-08-28
Branch: `cifra-rc4`

## Objetivo

O chat hoje trafega UTF-8 e não valida charset em ponto nenhum. O requisito é
que **apenas ASCII (0–127) circule na rede**, sem exceção, e que o sistema
continue funcionando sempre — nunca travando, corrompendo ou derrubando
conexão por causa de um caractere.

Em paralelo, os apelidos saem do produto: as mensagens passam a ser anônimas.

## Situação atual

### Arquitetura

`server.py` é um relay TCP cego: recebe bytes de um cliente e repassa aos
demais via `broadcast_raw()`, sem nunca chamar `cifrar()`/`decifrar()`. A cifra
e a chave são escolhidas localmente em cada `client.py` (`escolher_cifra()`) e
combinadas fora da rede. Essa separação é correta e deve ser preservada.

Três tipos de tráfego compartilham a mesma conexão, distinguidos por inspeção
de conteúdo no receptor:

| Tipo     | Exemplo                          | Cifrado |
| -------- | -------------------------------- | ------- |
| Controle | `/sair`, `NICK`                  | não     |
| Sistema  | `SYS:fulano entrou no chat :D`   | não     |
| Chat     | payload da cifra escolhida       | sim     |

Existem 10 chamadas de `.encode("utf-8")` / `.decode("utf-8")` espalhadas entre
`server.py` e `client.py`. Nenhuma validação de charset acompanha nenhuma delas.

### Defeitos confirmados por execução

Cada linha abaixo foi reproduzida rodando o código, não inferida por leitura.

| #  | Defeito                                                     | Evidência                                                              |
| -- | ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1  | Vigenère corrompe silenciosamente letras fora de A–Z         | `привет` → cifra `ekvkwh` (ASCII!) → decifra `cdvpsf` ≠ original       |
| 2  | Playfair derruba o cliente                                   | `ValueError: Letra 'П' não está na matriz`, não capturada em `write()` |
| 3  | Emoji e símbolos atravessam todas as cifras                  | `Bom dia 😀` → César → `ERP GLD 😀` sai na rede como UTF-8              |
| 4  | "Sem criptografia" é passagem livre                          | `preço €50` trafega cru, 100 % não-ASCII                                |
| 5  | Apelido nunca é validado nem cifrado                         | `José 😀` → `b'Jos\xc3\xa9 \xf0\x9f\x98\x80'` direto na rede            |
| 6  | `recv(1024)` corta caractere multibyte → `UnicodeDecodeError`| mensagem de 1023 chars terminando em emoji derruba a conexão            |
| 7  | Vigenère estoura `TypeError` com letra que expande no upper  | `ß`.upper() == `SS`, e `ord()` recebe string de tamanho 2               |
| 8  | `validar_chave` aceita chave em alfabeto não-ASCII           | Vigenère e monoalfabética usam `isalpha()`, verdadeiro para grego/cirílico |

Os defeitos 1, 2, 7 e 8 já estavam documentados como `diag_*` nas suítes de
teste existentes de Vigenère e Playfair. Este trabalho os corrige.

O defeito 6 desaparece por consequência: em ASCII, 1 caractere = 1 byte, então
`recv()` nunca parte um caractere ao meio.

## Decisão de escopo: acentos são normalizados, o resto é bloqueado

A seção 5 do enunciado **exige** que as cifras normalizem `Á→A` e `Ç→C`. Logo
acento já vira ASCII por especificação, e manter isso não conflita com o
requisito — o que trafega continua sendo ASCII puro.

A regra adotada é:

1. O texto passa pela normalização Unicode existente (NFD + descarte de marcas
   combinantes). `Ação` → `Acao`, `José` → `Jose`, `ñ` → `n`.
2. O que **sobrar** fora de 0–127 depois disso é **rejeitado**: emoji, `€`, `ß`,
   `æ`, cirílico, CJK, `°`, `ª`, travessão. Nada disso é convertido, adivinhado
   ou substituído — a mensagem simplesmente não é enviada.

A verificação NFD sozinha já resolve a cedilha (`ç` → `c` + marca combinante),
então o `replace("Ç", "C")` espalhado pelos módulos é redundante.

## Arquitetura da solução

### Novo módulo `ascii_puro.py` (raiz do projeto)

Ponto único de verdade sobre charset. Nem `client.py` nem `server.py` voltam a
chamar `encode`/`decode` diretamente.

```
ErroAscii(ValueError)              exceção única da camada

normalizar(texto)      -> str      NFD + descarte de marcas combinantes
eh_ascii(texto)        -> bool
caracteres_invalidos(texto) -> list[str]   os ofensores, sem repetição, em ordem
descrever_invalidos(texto)  -> str         "'😀' (U+1F600), '€' (U+20AC)"
validar(texto)         -> tuple[bool, str] mesmo contrato de validar_chave()
preparar(texto)        -> str      normaliza e valida; ErroAscii se sobrar algo
codificar(texto)       -> bytes    encode("ascii", errors="strict")
decodificar(dados)     -> str      valida byte a byte < 128 antes de decodificar
```

`validar()` devolve `(bool, str)` de propósito: é o mesmo contrato que os
módulos de cifra já usam em `validar_chave()`, então o código do cliente lida
com os dois do mesmo jeito.

### Defesa em profundidade: três camadas

Uma camada só não basta, porque um cliente adulterado pode pular a validação
de entrada e mandar bytes arbitrários direto no socket.

**Camada 1 — entrada do usuário (cliente).** Antes de cifrar, o texto digitado
é normalizado e validado. Se sobrar caractere não-ASCII, o cliente imprime
quais são e **não envia**, voltando ao prompt. Não desconecta, não trava.

**Camada 2 — saída para a rede (cliente e servidor).** Todo envio passa por
`codificar()`, que usa `errors="strict"`. É impossível um byte ≥ 0x80 sair do
processo: se algo escapou da camada 1, aqui vira exceção.

**Camada 3 — entrada vinda da rede (servidor e cliente).** Todo `recv()` passa
por `decodificar()`, que inspeciona os bytes antes de tentar interpretá-los.

O servidor é o ponto de estrangulamento da camada 3: um frame com qualquer
byte fora de 0–127 é **descartado e não repassado**, e o evento é registrado no
log do servidor com o endereço de origem. A conexão do cliente ofensor **não**
é derrubada — descartar o frame já cumpre o requisito, e derrubar tornaria
trivial para um cliente com bug perder a sessão inteira. O cliente receptor,
por sua vez, descarta o frame inválido e imprime um aviso, mantendo a sessão.

Isso garante o requisito mesmo contra um cliente modificado: o conteúdo não
chega a ninguém.

### Endurecimento das cifras (defesa em profundidade)

Com a camada 1 no lugar, caractere não-ASCII não deveria chegar às cifras. Mas
as cifras são módulos independentes, com suíte de testes própria, e não devem
travar nem corromper se receberem um. As trocas são de `isalpha()` — verdadeiro
para qualquer letra Unicode — por verificação explícita contra A–Z ASCII:

- `vigenere.cifrar/decifrar`: letra fora de A–Z passa direto, como pontuação
  (em vez de corromper). Corrige os defeitos 1 e 7.
- `vigenere.validar_chave` e `monoalfabetica.validar_chave`: rejeitam chave com
  letra fora de A–Z. Corrige o defeito 8.
- `playfair._extrair_letras` e `decifrar`: consideram apenas letras da matriz.
  Corrige o defeito 2.
- `cesar` e `monoalfabetica.cifrar`: já filtram por `in ALFABETO`, sem mudança.

As quatro cópias praticamente idênticas de `_normalizar` passam a delegar para
`ascii_puro.normalizar`. Cada módulo mantém o nome `_normalizar` porque
`tests/test_playfair.py` o chama diretamente.

**Fora de escopo:** os outros defeitos `diag_*` documentados nas suítes
(remoção heurística do X de preenchimento, `StopIteration` ao decifrar número
ímpar de letras, `ZeroDivisionError` com chave vazia). Não são problemas de
charset e continuam registrados como diagnóstico.

### Remoção dos apelidos

O handshake `NICK` deixa de existir nos dois lados. É uma mudança de protocolo,
então cliente e servidor mudam juntos.

**Cliente:** sai o `input("Digite seu apelido: ")`, sai o `recv` inicial que
esperava `NICK`, sai o ramo `if dado == "NICK"` de `receive()`. A mensagem
cifrada passa a ser o texto puro, sem o prefixo `f"{nickname}: "`.

**Servidor:** a lista `nicknames` é substituída por `enderecos`, mantida em
paralelo a `clients` pelo mesmo índice. O endereço serve só para o log técnico
do console do servidor — nunca é transmitido aos outros clientes. As mensagens
de sistema ficam anônimas: `Alguem entrou no chat :D` / `Alguem saiu do chat ;-;`.

Isso remove de brinde um gargalo: hoje `receive()` bloqueia em
`client.recv(1024)` esperando o apelido, serializando conexões novas.

## Fluxo de dados depois da mudança

Envio, no cliente:

```
input()
  -> ascii_puro.preparar()      camada 1: normaliza; rejeita e volta ao prompt
  -> modulo.cifrar()
  -> ascii_puro.codificar()     camada 2: strict, impossível vazar byte alto
  -> socket.send()
```

Relay, no servidor:

```
socket.recv()
  -> ascii_puro.decodificar()   camada 3: frame não-ASCII é descartado + logado
  -> broadcast_raw()            repassa os MESMOS bytes, sem decifrar
```

Recepção, no cliente:

```
socket.recv()
  -> ascii_puro.decodificar()   camada 3: frame inválido é descartado + avisado
  -> despacho: /sair | SYS: | conteúdo de chat
  -> modulo.decifrar()
```

## Tratamento de erros

| Situação                                | Comportamento                                        |
| --------------------------------------- | ----------------------------------------------------- |
| Usuário digita emoji                    | avisa quais caracteres, não envia, volta ao prompt     |
| Usuário digita só acento (`ação`)       | normaliza para `ACAO` e envia normalmente              |
| Servidor recebe frame não-ASCII         | descarta, loga com o endereço, não repassa, não derruba |
| Cliente recebe frame não-ASCII          | descarta, avisa no terminal, mantém a sessão           |
| Chave com letra não-ASCII               | `validar_chave` rejeita, pede outra                    |

Nenhum caminho de erro encerra a conexão. O requisito é que o ASCII sempre
funcione, e uma entrada inválida é um evento comum, não fatal.

## Testes

Nova suíte `tests/test_ascii_puro.py`, no mesmo formato standalone das
existentes (`rodar_todos()`, saída `[OK]`/`[FALHA]`, sem pytest — o projeto não
tem pytest instalado). Cobre:

- `normalizar` converte acento e cedilha; não inventa conversão para emoji
- `eh_ascii` nos limites: `chr(127)` verdadeiro, `chr(128)` falso
- `caracteres_invalidos` sem repetição e em ordem de aparição
- `validar` no contrato `(bool, str)`
- `preparar` aceita acento, rejeita emoji/`€`/cirílico/`ß`
- `codificar` levanta `ErroAscii` em vez de gerar bytes altos
- `decodificar` rejeita bytes ≥ 0x80 e aceita todo o intervalo 0–127
- ida e volta `codificar`/`decodificar` para os 128 caracteres

As suítes existentes de César, monoalfabética, Playfair e Vigenère devem
continuar passando (13, 12, 33 e 17 testes). Os `diag_*` de charset passam a
reportar "defeito parece corrigido".

Duas suítes hoje **crasham no Windows** com `UnicodeEncodeError` porque
imprimem caracteres não-ASCII num console cp1252 — o mesmo bug de charset, uma
camada acima. As mensagens de diagnóstico passam a identificar os caracteres
por código (`U+03A9`) em vez de imprimi-los literalmente, tornando as suítes
executáveis sem depender de `PYTHONIOENCODING`.

## Critérios de aceitação

1. Nenhum byte ≥ 0x80 atravessa o socket, em nenhum caminho, nem com cliente adulterado.
2. Nenhuma entrada de usuário derruba cliente ou servidor.
3. Texto acentuado continua funcionando, normalizado, como o enunciado exige.
4. Nenhuma referência a apelido resta em `client.py` ou `server.py`.
5. Todas as suítes rodam em console cp1252 sem `UnicodeEncodeError`.
6. As 75 asserções existentes continuam passando.
