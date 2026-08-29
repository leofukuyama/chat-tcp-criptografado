"""
Enquadramento de mensagens do chat.

O PROBLEMA. TCP é um fluxo de BYTES, não de mensagens. O código antigo
tratava cada recv() como se fosse exatamente um send(), e isso é falso nos
dois sentidos:

  - duas mensagens enviadas em sequência rápida chegam GRUDADAS em um único
    recv(), e eram decifradas como se fossem uma só. Efeito real observado:
    "OLA MUNDO/PXFOPVP:XIFZB..." em vez de "OLA MUNDO". Na Playfair o
    resultado tende a ter número ímpar de letras, o que derruba o cliente;
  - uma mensagem maior que o buffer chega PICADA, e cada pedaço era tratado
    como uma mensagem inteira.

A SOLUÇÃO. Cada mensagem vira um "quadro" com cabeçalho de tamanho fixo:

    M 0011 HELLO WORLD
    │  │    └── payload
    │  └── tamanho do payload, 4 dígitos decimais (máximo 9999)
    └── tipo: M=mensagem  S=sistema  C=controle

Saber o tamanho de antemão resolve os dois casos: o receptor lê exatamente
N bytes, nem mais nem menos, acumulando entre recv() quando preciso.

POR QUE O TAMANHO EM DÍGITOS DECIMAIS, e não em bytes binários? Porque o
cabeçalho também trafega. Um tamanho binário colocaria bytes >= 0x80 na rede
(11 viraria 0x0B, mas 200 viraria 0xC8) e quebraria o requisito de ASCII
puro. Com dígitos, o quadro inteiro continua ASCII e verificável byte a byte.

POR QUE NÃO UM DELIMITADOR (\\n)? Seria mais simples, mas: (1) dependeria de
o payload nunca conter \\n, uma invariante frágil que só vale enquanto
ninguém mudar as cifras; (2) um payload corrompido levaria o resto do fluxo
junto, sem como ressincronizar. Com o tamanho no cabeçalho, sabemos onde o
quadro ruim termina e pulamos só ele.

POR QUE O TIPO NO CABEÇALHO. Antes, o receptor adivinhava a natureza da
mensagem inspecionando o conteúdo (`if dado == "/sair"`,
`if dado.startswith("SYS:")`). Isso permitia falsificação: com a opção "sem
criptografia", bastava digitar "SYS:Admin: mandem a chave" para a mensagem
aparecer como aviso oficial do servidor. Com o tipo no cabeçalho, o servidor
é o único que emite quadros S -- e recusa um S vindo de cliente. A
falsificação deixa de ser possível por construção, não por checagem.
"""

from typing import NamedTuple, Optional

import ascii_puro

TAMANHO_CAMPO_TIPO = 1
TAMANHO_CAMPO_TAMANHO = 4
TAMANHO_CABECALHO = TAMANHO_CAMPO_TIPO + TAMANHO_CAMPO_TAMANHO

# Com 4 dígitos decimais o maior payload possível é 9999 bytes. Mensagens de
# chat digitadas à mão ficam MUITO abaixo disso.
PAYLOAD_MAXIMO = 10 ** TAMANHO_CAMPO_TAMANHO - 1

TIPO_MENSAGEM = "M"   # conteúdo de chat, cifrado -- o servidor só repassa
TIPO_SISTEMA = "S"    # aviso gerado pelo servidor, nunca cifrado
TIPO_CONTROLE = "C"   # comando (/sair), nunca cifrado

TIPOS_VALIDOS = (TIPO_MENSAGEM, TIPO_SISTEMA, TIPO_CONTROLE)

# Tipos que um CLIENTE pode legitimamente enviar. O S está fora de propósito:
# é o que impede um cliente de forjar um aviso do servidor.
TIPOS_PERMITIDOS_DO_CLIENTE = (TIPO_MENSAGEM, TIPO_CONTROLE)


class ErroProtocolo(ValueError):
    """
    Levantada quando o CABEÇALHO está corrompido -- tipo desconhecido,
    tamanho não numérico, byte não-ASCII.

    É sempre fatal para a conexão, e essa é a diferença em relação a um
    payload inválido: sem um tamanho confiável não há como saber onde o
    quadro termina, logo não há como pular o quadro ruim e continuar. O
    fluxo está perdido, e a única saída honesta é encerrar a conexão em vez
    de seguir interpretando lixo.
    """


class Quadro(NamedTuple):
    """
    Uma mensagem completa extraída do fluxo.

    tipo             M, S ou C.
    bytes_completos  cabeçalho + payload, exatamente como vieram. O servidor
                     repassa ISTO, sem tocar no payload -- ele não tem a
                     chave e não deve conseguir ler o conteúdo.
    texto            payload decodificado, ou None se o payload não for
                     ASCII (quadro a descartar).
    erro             motivo, vazio quando o quadro está bom.
    """

    tipo: str
    bytes_completos: bytes
    texto: Optional[str]
    erro: str


def empacotar(tipo: str, texto: str) -> bytes:
    """
    Monta um quadro pronto para ir ao socket.

    >>> empacotar(TIPO_MENSAGEM, "HELLO")
    b'M0005HELLO'
    >>> empacotar(TIPO_CONTROLE, "")
    b'C0000'
    """
    if tipo not in TIPOS_VALIDOS:
        raise ErroProtocolo(f"tipo de quadro desconhecido: {tipo!r}")

    # Reaproveita a camada 2 da defesa ASCII: errors="strict", então é
    # impossível um byte >= 0x80 entrar no payload.
    payload = ascii_puro.codificar(texto)

    if len(payload) > PAYLOAD_MAXIMO:
        raise ErroProtocolo(
            f"mensagem de {len(payload)} caracteres passa do limite de "
            f"{PAYLOAD_MAXIMO}"
        )

    cabecalho = f"{tipo}{len(payload):0{TAMANHO_CAMPO_TAMANHO}d}"
    return ascii_puro.codificar(cabecalho) + payload


class Desempacotador:
    """
    Acumula os bytes que chegam do socket e devolve mensagens completas.

    Uma instância POR CONEXÃO: o buffer é o estado parcial daquele fluxo
    específico, e misturar dois clientes no mesmo desempacotador
    embaralharia as mensagens de ambos.

    Uso:
        d = Desempacotador()
        for quadro in d.alimentar(sock.recv(1024)):
            ...
    """

    def __init__(self):
        self._buffer = bytearray()

    def alimentar(self, dados: bytes) -> list[Quadro]:
        """
        Junta `dados` ao que já havia e extrai todos os quadros completos.

        Devolve lista vazia quando ainda falta byte para fechar o quadro
        atual -- é o caso normal de uma mensagem picada, não um erro.

        Levanta ErroProtocolo se o cabeçalho estiver corrompido (ver a
        docstring da exceção: nesse caso não há como continuar).
        """
        self._buffer.extend(dados)

        quadros = []
        while True:
            quadro = self._extrair_um()
            if quadro is None:
                return quadros
            quadros.append(quadro)

    def _extrair_um(self) -> Optional[Quadro]:
        """Um quadro, ou None se ainda não há bytes suficientes."""
        if len(self._buffer) < TAMANHO_CABECALHO:
            return None

        tipo, tamanho = self._ler_cabecalho()

        fim = TAMANHO_CABECALHO + tamanho
        if len(self._buffer) < fim:
            # Payload incompleto. Note que o cabeçalho NÃO é consumido: ele
            # é relido na próxima chamada, quando o resto tiver chegado.
            return None

        bytes_completos = bytes(self._buffer[:fim])
        payload = bytes_completos[TAMANHO_CABECALHO:]
        del self._buffer[:fim]

        # Payload não-ASCII é um problema do CONTEÚDO, não do enquadramento.
        # Como o tamanho já foi lido, o quadro seguinte continua alinhado --
        # marcamos este como inválido e a conexão segue viva.
        try:
            texto = ascii_puro.decodificar(payload)
        except ascii_puro.ErroAscii as erro:
            return Quadro(tipo, bytes_completos, None, str(erro))

        return Quadro(tipo, bytes_completos, texto, "")

    def _ler_cabecalho(self) -> tuple[str, int]:
        """Interpreta os 5 primeiros bytes do buffer, sem consumi-los."""
        bruto = bytes(self._buffer[:TAMANHO_CABECALHO])

        try:
            cabecalho = ascii_puro.decodificar(bruto)
        except ascii_puro.ErroAscii as erro:
            raise ErroProtocolo(f"cabeçalho não-ASCII: {erro}") from erro

        tipo = cabecalho[0]
        campo_tamanho = cabecalho[1:]

        if tipo not in TIPOS_VALIDOS:
            raise ErroProtocolo(
                f"tipo de quadro desconhecido: {tipo!r} "
                f"(cabeçalho recebido: {cabecalho!r})"
            )

        if not campo_tamanho.isdigit():
            raise ErroProtocolo(
                f"tamanho inválido no cabeçalho: {campo_tamanho!r} "
                "-- o outro lado parece estar falando outro protocolo"
            )

        return tipo, int(campo_tamanho)
