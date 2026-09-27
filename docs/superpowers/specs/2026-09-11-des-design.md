# Design: Cifra DES no chat-tcp-criptografado

## Contexto

O chat já tem 6 opções de cifra registradas em `cifras/registro.py` e selecionadas
localmente em `client.py` (`escolher_cifra()`), sem qualquer envolvimento do
servidor (`server.py` só encaminha bytes, nunca cifra/decifra). Cada cifra vive em
seu próprio módulo `cifras/<nome>.py`, expondo o contrato:

- `validar_chave(chave: str) -> tuple[bool, str]`
- `cifrar(texto: str, chave: str) -> str`
- `decifrar(texto: str, chave: str) -> str`
- (opcional) `bytes_brutos(texto_cifrado: str) -> bytes` — só quando o criptograma
  não é ASCII "de fábrica" e precisa de Base64 para transporte (caso do RC4).

O objetivo desta atividade é implementar o **DES (Data Encryption Standard)** do
zero (sem bibliotecas prontas de criptografia), seguindo a explicação de
`README-DES.md` (já commitado nesta branch), e integrá-lo como uma sétima opção no
menu do cliente.

## Decisão: chave ASCII vs. chave hexadecimal

A chave de exemplo do PDF (`01 23 45 67 89 AB CD EF`) representa bytes brutos, e
vários desses bytes (`0x89`, `0xAB`, `0xCD`, `0xEF`) estão fora do intervalo ASCII
(0-127) que este projeto impõe a toda chave digitada no prompt `Chave:`
(`ascii_puro.py` é o único ponto de verdade sobre charset do projeto).

**Decisão:** a chave digitada no chat continua sendo uma senha em ASCII, como nas
outras 5 cifras — normalizada (sem acento), rejeitada se vazia ou se tiver mais de
8 caracteres, e completada com zeros à direita se tiver menos de 8 (mesmo
princípio de padding autorizado pelo professor, aplicado aqui à chave curta).

O **motor DES** (tabelas, geração de subchaves, função F, cifra/decifra de um
bloco de 8 bytes) é implementado como funções internas que operam sobre **bytes
crus (0-255)**, sem essa restrição ASCII — é contra essas funções que os vetores
de teste clássicos (que usam bytes fora do ASCII) são validados. Só a camada
exposta ao chat (`validar_chave`/`cifrar`/`decifrar`) impõe ASCII, exatamente como
o RC4 já separa `_preparar_chave` (ASCII) de `_rc4_xor` (bytes crus).

## Arquitetura

### `cifras/des.py` (novo módulo)

**Tabelas fixas do DES** (todas transcritas de `README-DES.md` / slides da
disciplina, padrão FIPS 46-3): `IP`, `IP_INV`, `PC1`, `PC2`, `E_TABELA`,
`P_TABELA`, `S_BOXES` (8 caixas 4×16), `DESLOCAMENTOS` (lista de 16 valores 1/2).

**Funções de bit-manipulação:**
- `_bytes_para_bits(dados: bytes) -> list[int]`
- `_bits_para_bytes(bits: list[int]) -> bytes`
- `_permutar(bits: list[int], tabela: list[int]) -> list[int]` (tabelas são
  1-indexadas, como na especificação original)
- `_deslocar_esquerda(bits: list[int], n: int) -> list[int]`
- `_xor(a: list[int], b: list[int]) -> list[int]`

**Núcleo do algoritmo:**
- `_gerar_subchaves(chave_bytes: bytes) -> list[list[int]]` — PC-1, divide em
  C0/D0, aplica deslocamentos e PC-2 por 16 rodadas, devolve `[K1, ..., K16]`
  (cada uma 48 bits).
- `_funcao_f(bits_r: list[int], subchave: list[int]) -> list[int]` — expansão E
  (32→48), XOR com a subchave, substituição pelas 8 S-BOX (48→32), permutação P.
- `_cifrar_bloco(bloco: bytes, subchaves: list[list[int]]) -> bytes` — IP, 16
  rodadas de Feistel com `K1..K16`, troca de metades, IP⁻¹. Bloco sempre 8
  bytes; `subchaves` vem de `_gerar_subchaves()` (permite calcular o key
  schedule uma única vez por mensagem, em vez de uma vez por bloco).
- `_decifrar_bloco(bloco: bytes, subchaves: list[list[int]]) -> bytes` — mesma
  estrutura, subchaves aplicadas na ordem inversa (`K16..K1`).

**Contrato do chat:**
- `validar_chave(chave: str) -> tuple[bool, str]` — normaliza (remove acento),
  exige ASCII, rejeita vazia, rejeita mais de 8 caracteres.
- `_preparar_chave(chave: str) -> bytes` — valida e converte para exatamente 8
  bytes, completando com `0x00` à direita se for mais curta (mesmo padrão de
  `rc4._preparar_chave`).
- `cifrar(texto: str, chave: str) -> str` — normaliza o texto, codifica em bytes
  (`ascii_puro.codificar`), divide em blocos de 8 bytes com padding de `0x00` no
  último bloco, cifra cada bloco com `_cifrar_bloco` (ECB — mesmo que o exemplo do
  PDF faz), concatena e devolve em Base64.
- `decifrar(texto: str, chave: str) -> str` — decodifica Base64 (tolerante a lixo,
  nunca lança exceção — mesmo padrão de `rc4._base64_decode_tolerante`), decifra
  cada bloco completo de 8 bytes, remove os zeros de padding do final
  (`rstrip(b"\x00")`), decodifica para string com
  `errors="backslashreplace"` (chave errada produz texto ilegível, não exceção).
- `bytes_brutos(texto_cifrado: str) -> bytes` — mesmo papel que em `rc4.py`:
  expõe o criptograma decodificado do Base64, para o `client.py` mostrar
  `[CIFRADO decimal]` (ele já detecta essa função via `hasattr`, sem precisar
  mexer em `client.py`).

### `cifras/registro.py`

Adiciona `"7": des` em `CIFRAS` e `"7": "Cifra DES"` em `NOMES`.

### `server.py` / `client.py`

**Nenhuma mudança.** O menu é gerado a partir de `NOMES` (loop `for opcao, nome in
NOMES.items()`), e a exibição de `bytes_brutos` já é genérica via `hasattr`.

## Testes (`tests/test_des.py`)

Mesmo formato dos demais (`TESTES = [...]` + `rodar_todos()`, sem framework
externo). Casos:

1. `validar_chave`: aceita 1-8 chars ASCII, rejeita vazia, rejeita >8, rejeita
   não-ASCII, normaliza acento.
2. **Vetor clássico do livro-texto** (Stallings/Forouzan, amplamente citado):
   `M = 0123456789ABCDEF`, `K = 133457799BBCDFF1` → `C = 85E813540F0AB405`,
   chamando `_cifrar_bloco` diretamente com `bytes.fromhex(...)` (chave e
   plaintext aqui têm bytes fora do ASCII, então o teste vai direto no motor,
   não em `cifrar()`).
3. **Exemplo passo a passo do PDF** ("Atacar base norte.", chave hex
   `0123456789ABCDEF`): comparação de subchaves (K1, K2) e das rodadas 1-3 do
   primeiro bloco (`E(R0)`, XOR com a subchave, saída das S-BOX, `f`, `L1/R1`,
   `L2/R2`, `L3/R3`) contra os valores exatos dos slides — garante que cada
   tabela foi transcrita certa, não só que cifrar/decifrar são inversos.
4. **Mensagem completa do PDF fim-a-fim**: os 24 bytes de criptograma
   (`30 44 35 1B ... 9A 96 E9 88`) batendo com `_cifrar_bloco` aplicado aos 3
   blocos de 8 bytes da mensagem com padding.
5. Round-trip via `cifrar()`/`decifrar()` com chave ASCII curta (padded) e de
   exatamente 8 caracteres.
6. Chave errada não recupera o texto original.
7. `decifrar()` nunca lança exceção com lixo/Base64 inválido (mesmo teste do
   RC4, adaptado).
8. Texto vazio produz criptograma vazio.

## Fora de escopo (por decisão explícita)

- Padding "de verdade" (PKCS#5/7) — o professor autorizou zeros simples.
- Modos de operação além de ECB (CBC, CTR, etc.) — não foi ensinado ainda.
- Seção nova no `README.md` principal — só código + testes por agora.
- Qualquer mudança em `server.py` — ele continua cego a qual cifra está ativa.
