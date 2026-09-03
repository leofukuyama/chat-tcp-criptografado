"""
Cifra de fluxo RC4 (Rivest Cipher 4, 1987).

Diferença fundamental em relação às outras quatro cifras deste projeto:
RC4 não é uma cifra de SUBSTITUIÇÃO sobre um alfabeto de 26 letras -- é uma
cifra de FLUXO que opera sobre BYTES. Ela gera um "keystream" pseudoaleatório
a partir da chave e faz XOR byte a byte com o texto:

    C_i = P_i XOR K_i     |     P_i = C_i XOR K_i   (XOR é sua própria inversa)

Isso tem duas consequências que não existem em nenhuma outra cifra do
catálogo:

  1. O criptograma é BYTES ARBITRÁRIOS (0-255), não mais texto ASCII. A rede
     deste projeto só aceita 0-127 (ascii_puro.py, seção 5 do README). Por
     isso cifrar() aqui produz o criptograma em Base64 -- só letras, dígitos,
     "+", "/" e "=", todos ASCII -- em vez de devolver os bytes crus. Esse é
     o "custo de transporte" citado no README como extensão natural do
     projeto original.
  2. RC4 destrói completamente o "formato" da mensagem: cada byte do texto,
     incluindo espaços e pontuação, é transformado. Nas outras cifras dá
     para reconhecer o tamanho e a pontuação da mensagem original olhando o
     criptograma ("DWDTXH DR DPDQKHFHU, 05K!" ainda tem vírgula e espaços no
     lugar certo); em RC4 isso desaparece -- o criptograma em Base64 nem tem
     o mesmo comprimento visual do texto original.

Chave: qualquer sequência de 1 a 256 bytes ASCII (letras, dígitos, símbolos,
espaço -- tudo vale, e MAIÚSCULA/minúscula importa). Isso é deliberadamente
diferente do Vigenère, que só aceita A-Z: lá a chave indexa um alfabeto de 26
posições; aqui a chave é matéria-prima de bytes para o gerador de keystream,
então cada bit dela conta. Uppercasear a chave (como César/monoalfabética
fazem) jogaria fora metade do espaço de chaves de graça.

O ALGORITMO tem duas fases clássicas:

  KSA (Key-Scheduling Algorithm) -- embaralha uma tabela S de 256 bytes
  usando a chave, uma única vez, no início.

  PRGA (Pseudo-Random Generation Algorithm) -- a cada byte de saída,
  embaralha S um pouco mais e produz um byte de keystream.

FRAQUEZAS CONHECIDAS (motivo de RC4 estar tecnicamente obsoleto, apesar de o
espaço de chaves nominal ser enorme -- até 2^2048 -- e não cair para força
bruta nem análise de frequência como as outras cifras do catálogo):

  - Os primeiros bytes do keystream são estatisticamente enviesados
    (Mantin & Shamir, 2001) -- a mitigação de mercado é descartar os
    primeiros 256 bytes gerados ("RC4-drop[256]"), o que este módulo NÃO
    faz de propósito: implementar o RC4 "de livro-texto" mantém o resultado
    verificável contra os vetores de teste canônicos da literatura.
  - Reuso de chave entre mensagens (exatamente o que este chat faz -- chave
    estática pela sessão inteira) expõe o keystream a ataques de XOR entre
    criptogramas diferentes cifrados com a mesma chave.
  - O ataque FMS (Fluhrer, Mantin & Shamir, 2001) explorou vieses do RC4
    contra o protocolo WEP, e a IETF proibiu RC4 em TLS pela RFC 7465 (2015).

Isso encaixa no mesmo argumento pedagógico do quadro comparativo do README
(seção 6.8): espaço de chaves grande não é sinônimo de segurança -- aqui,
diferente das cifras clássicas, o que falha não é a falta de difusão, e sim
um viés estatístico sutil no gerador de números pseudoaleatórios.
"""

import base64
import binascii

import ascii_puro

# Tamanho da tabela S do RC4. Uma chave maior que isso não aumenta a
# segurança -- ela só repetiria posições já cobertas pelo KSA.
TAMANHO_MAXIMO_CHAVE = 256


def validar_chave(chave: str) -> tuple[bool, str]:
    """
    Regras:
      - não pode ser vazia
      - só ASCII depois de normalizada (sem acento)
      - no máximo 256 bytes (tamanho da tabela S; ver docstring do módulo)

    Ao contrário do Vigenère, QUALQUER caractere ASCII vale -- número,
    símbolo, espaço -- porque a chave aqui não indexa um alfabeto de 26
    letras, é matéria-prima de bytes para o KSA.

    >>> validar_chave("Senha123!")
    (True, '')
    >>> validar_chave("")
    (False, 'A chave não pode ser vazia.')
    """
    chave_normalizada = ascii_puro.normalizar(chave)

    if not chave_normalizada:
        return False, "A chave não pode ser vazia."

    valida, erro = ascii_puro.validar(chave_normalizada)
    if not valida:
        return False, f"A chave deve conter apenas caracteres ASCII ({erro})."

    if len(chave_normalizada) > TAMANHO_MAXIMO_CHAVE:
        return False, f"A chave deve ter no máximo {TAMANHO_MAXIMO_CHAVE} caracteres."

    return True, ""


def _preparar_chave(chave: str) -> bytes:
    """
    Valida e converte a chave para bytes, prontos para o KSA.

    Mesmo raciocínio do vigenere._preparar_chave(): cifrar()/decifrar() não
    podem confiar que o chamador já rodou validar_chave() antes (o chat
    valida, mas testes e outros chamadores podem não validar). Sem esta
    checagem, chave vazia estouraria ZeroDivisionError lá dentro do KSA, em
    "chave[i % len(chave)]" -- um erro que não diz nada sobre a causa real.

    >>> _preparar_chave("Key")
    b'Key'
    """
    valida, erro = validar_chave(chave)
    if not valida:
        raise ValueError(erro)
    return ascii_puro.normalizar(chave).encode("ascii")


def _ksa(chave: bytes) -> list[int]:
    """
    Key-Scheduling Algorithm: embaralha uma tabela S de 256 bytes usando a
    chave. Roda uma única vez, no início, antes de gerar qualquer keystream.

    A chave "repete ciclicamente" via "i % len(chave)", igual ao mecanismo
    do Vigenère (chave[i % m]) -- só que aqui é para inicializar uma tabela
    de 256 posições, não para deslocar letras.
    """
    S = list(range(256))
    j = 0
    tamanho_chave = len(chave)

    for i in range(256):
        j = (j + S[i] + chave[i % tamanho_chave]) % 256
        S[i], S[j] = S[j], S[i]  # troca de posição -- é isso que embaralha a tabela

    return S


def _prga(S: list[int], quantidade: int) -> bytes:
    """
    Pseudo-Random Generation Algorithm: produz `quantidade` bytes de
    keystream a partir da tabela S já embaralhada pelo KSA.

    A cada byte gerado, S é embaralhada um pouco mais -- é o que faz o
    keystream não se repetir a cada 256 bytes (diferente de um XOR com uma
    chave curta reaproveitada sem essa etapa, que seria trivialmente
    periódico e cairia nos mesmos ataques do Vigenère).
    """
    S = list(S)  # cópia -- não pode mexer na tabela que o chamador ainda usa
    i = j = 0
    keystream = bytearray()

    for _ in range(quantidade):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])

    return bytes(keystream)


def _rc4_xor(dados: bytes, chave: bytes) -> bytes:
    """
    Aplica o RC4 a `dados`: gera um keystream do mesmo tamanho e faz XOR
    byte a byte. Como XOR é sua própria inversa, esta MESMA função serve
    para cifrar E para decifrar -- é o que torna RC4 uma cifra simétrica de
    fluxo (não existe um "sentido inverso" separado, ao contrário de
    cesar.decifrar(), que precisa negar o deslocamento).

    Vetor de teste canônico da literatura (chave "Key", texto "Plaintext"):

    >>> _rc4_xor(b"Plaintext", b"Key").hex()
    'bbf316e8d940af0ad3'
    """
    S = _ksa(chave)
    keystream = _prga(S, len(dados))
    return bytes(byte ^ k for byte, k in zip(dados, keystream))


def cifrar(texto: str, chave: str) -> str:
    """
    Cifra um texto usando RC4 e devolve o criptograma em Base64.

    Diferente das outras cifras, o texto NÃO é uppercased -- RC4 trabalha
    byte a byte, então maiúscula e minúscula são só bytes diferentes que o
    keystream trata normalmente, sem precisar de normalização de caixa.

    A conversão para bytes reaproveita ascii_puro.codificar() -- a mesma
    CAMADA 2 usada por protocolo.empacotar() -- porque RC4 precisa mesmo de
    bytes reais para o XOR, não só de uma string Python. Na prática, quando
    chamado a partir do client.py, o texto já passou pela camada 1
    (ascii_puro.preparar()) antes de chegar aqui, então nunca sobra
    caractere não-ASCII; esta chamada é a mesma rede de segurança que as
    outras cifras já aplicam à CHAVE, aplicada aqui ao TEXTO.

    Base64, não hexadecimal: hexadecimal dobraria o tamanho (2 caracteres
    por byte contra ~1,33 do Base64), e o quadro do protocolo tem um limite
    fixo de 9999 bytes de payload (protocolo.PAYLOAD_MAXIMO).

    >>> cifrar("Plaintext", "Key")
    'u/MW6NlArwrT'
    """
    chave_bytes = _preparar_chave(chave)
    texto_normalizado = ascii_puro.normalizar(texto)
    dados = ascii_puro.codificar(texto_normalizado)

    cifrado_bytes = _rc4_xor(dados, chave_bytes)
    return base64.b64encode(cifrado_bytes).decode("ascii")


def _base64_decode_tolerante(texto: str) -> bytes:
    """
    Decodifica Base64 sem NUNCA lançar exceção -- extraído para uso tanto
    de decifrar() quanto de bytes_brutos() (exibição/depuração).

    Duas coisas podem impedir uma decodificação limpa:

      1. `texto` tem caractere fora do ASCII. Não deveria acontecer vindo
         da rede (a camada 3 do protocolo -- ascii_puro.decodificar() --
         já barra isso antes de quadro.texto existir), mas bytes_brutos()
         promete funcionar com "qualquer texto", então a garantia precisa
         valer também para quem chama fora desse caminho (testes, um
         script). base64.b64decode() faz esse encode("ascii") sozinho
         quando recebe uma str, e SEM validate=True o erro sai como
         ValueError, não binascii.Error -- por isso o encode é feito aqui
         primeiro, descartando o que não for ASCII, para o erro nunca
         escapar por essa porta.
      2. `texto` (já garantidamente ASCII) não é Base64 válido -- por
         exemplo, se o remetente escolheu outra cifra, ou fala outro
         protocolo. base64.b64decode() com validate=False já ignora
         sozinho caracteres fora do alfabeto Base64; o padding é
         completado manualmente aqui para não estourar "Incorrect
         padding", e o que ainda assim falhar (raro) cai no fallback dos
         bytes crus do próprio texto.
    """
    texto_ascii = texto.encode("ascii", errors="ignore").decode("ascii")
    texto_com_padding = texto_ascii + "=" * (-len(texto_ascii) % 4)
    try:
        return base64.b64decode(texto_com_padding, validate=False)
    except binascii.Error:
        # Nem com o padding completado deu para interpretar como Base64
        # (ex.: sobrou uma quantidade de caracteres válidos que não fecha em
        # bytes inteiros). Não é um erro de ENQUADRAMENTO -- o quadro chegou
        # certinho, o conteúdo é que não é RC4 -- então seguimos com os
        # bytes crus do texto em vez de desistir.
        return texto_ascii.encode("ascii", errors="ignore")


def bytes_brutos(texto_cifrado: str) -> bytes:
    """
    Devolve o criptograma em bytes CRUS (0-255), decodificando o Base64 de
    volta -- é o mesmo número que aparece no "Texto Cript." dos gabaritos
    de teste da disciplina (uma lista de inteiros decimais), diferente do
    texto em Base64 que efetivamente trafega na rede e aparece no console
    do chat.

    Existe só para EXIBIÇÃO/depuração (ex.: comparar com um caso de teste,
    ou mostrar no chat o mesmo formato numérico do gabarito) -- cifrar() e
    decifrar() não dependem desta função, e ela nunca lança exceção pelo
    mesmo motivo de decifrar(): pode ser chamada com qualquer texto vindo
    da rede, inclusive lixo.

    Extensão OPCIONAL do contrato das cifras (ver cifras/sem_criptografia.py):
    só existe aqui porque o criptograma do RC4 não é ASCII "de fábrica"
    como o das outras cinco cifras -- um chamador pode testar
    `hasattr(modulo, "bytes_brutos")` antes de usar.

    >>> bytes_brutos(cifrar("Plaintext", "Key")).hex()
    'bbf316e8d940af0ad3'
    """
    return _base64_decode_tolerante(texto_cifrado)


def decifrar(texto: str, chave: str) -> str:
    """
    Decifra um criptograma em Base64 de volta ao texto original.

    Duas coisas podem dar errado aqui e NENHUMA pode derrubar o cliente
    (mesma regra do playfair.decifrar() -- "decifrar lixo tem que produzir
    lixo, não uma queda"), porque client.py chama decifrar() direto na
    thread de recepção, sem try/except:

      1. `texto` pode não ser Base64 válido (ver _base64_decode_tolerante).
      2. A chave pode estar errada. Nesse caso o XOR produz bytes fora do
         intervalo ASCII quase sempre (cada byte tem ~50% de chance de sair
         >= 0x80) -- decode("ascii", errors="backslashreplace") troca cada
         byte problemático por um escape tipo "\\xF3" em vez de estourar
         UnicodeDecodeError. O resultado fica ilegível (é lixo mesmo, de
         propósito -- prova que a chave está errada), mas nunca quebra.

    >>> decifrar("u/MW6NlArwrT", "Key")
    'Plaintext'
    """
    chave_bytes = _preparar_chave(chave)
    cifrado_bytes = _base64_decode_tolerante(texto)
    dados = _rc4_xor(cifrado_bytes, chave_bytes)
    return dados.decode("ascii", errors="backslashreplace")
