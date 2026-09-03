"""
Utilitário de apoio à captura no Wireshark -- NÃO faz parte do chat
(client.py/server.py não importam nada daqui). Serve só para conferir, com
calma, que os bytes vistos na rede realmente correspondem à cifra RC4 da
mensagem combinada -- sem precisar decifrar de cabeça durante a
apresentação.

COMO CAPTURAR (127.0.0.1 é loopback -- uma interface de rede comum do
Windows NÃO enxerga esse tráfego, é a causa mais comum de "não aparece
nada" no Wireshark):

  1. Na lista de interfaces do Wireshark, use "Adapter for loopback
     traffic capture" (Npcap) -- já vem com a instalação padrão do
     Wireshark no Windows. Sem essa interface na lista, reinstale o Npcap
     marcando "Support loopback traffic capture" (ou use o RawCap como
     alternativa). Se preferir não mexer nisso, dá pra rodar o servidor
     com host="0.0.0.0" e conectar os clientes pelo IP real da máquina
     (ou de duas máquinas na mesma rede) -- aí é tráfego comum, qualquer
     interface Wi-Fi/Ethernet capta.
  2. Filtro de exibição: tcp.port == 64146
  3. Suba o servidor, os dois clientes (mesma cifra RC4, mesma chave), e
     mande uma mensagem.
  4. Clique com o botão direito no pacote de dados (não no handshake) ->
     Follow -> TCP Stream. Na janela que abre, troque "Entire
     conversation" para UM SÓ SENTIDO (ex.: "clientA -> servidor") --
     misturar os dois sentidos quebra o enquadramento tipo+tamanho+payload
     (protocolo.py), porque são dois fluxos de bytes independentes.
  5. Troque a vista para "ASCII" (não hex nem C Arrays -- o quadro inteiro
     já É ASCII por construção, ver ascii_puro.py). Copie o texto.

COMO CONFERIR (três modos):

  ANTES de capturar -- calcular o quadro esperado, pra saber o que
  procurar:

      python scripts/verificar_wireshark.py cifrar "mensagem" "chave"

  DEPOIS de capturar -- colar o que o Wireshark mostrou (pode ser um
  quadro só, ou o trecho inteiro de um sentido do stream, com vários
  quadros grudados -- o parser é o mesmo protocolo.Desempacotador que o
  chat usa) e conferir que decifra para a mensagem original:

      python scripts/verificar_wireshark.py decifrar "M0044u/MW6NlArwrT..." "chave"

  PARA A APRESENTAÇÃO -- roda os três casos de teste que o professor deu
  (T1/T2/T3, mesmo texto plano, chaves de 8/97/253 bytes) e imprime lado a
  lado o que o gabarito espera e o que esta implementação produz, sem
  precisar digitar nada:

      python scripts/verificar_wireshark.py gabarito
"""

import base64
import binascii
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import protocolo
from cifras import rc4


# Vetores de teste fornecidos pela disciplina (slides/.txt) -- os mesmos
# dados de tests/test_rc4.py::teste_vetores_da_disciplina. Duplicados aqui
# de propósito: são dados de referência estáticos, não lógica a manter, e
# um script de demonstração não deveria importar de dentro de tests/.
TEXTO_PLANO_ASCII = [
    67, 121, 98, 101, 114, 115, 101, 99, 117, 114, 105, 116, 121, 32, 109,
    101, 108, 104, 111, 114, 32, 100, 105, 115, 99, 105, 112, 108, 105,
    110, 97, 32, 100, 111, 32, 99, 117, 114, 115, 111, 46,
]

VETORES_DA_DISCIPLINA = {
    "T1": {
        "chave_ascii": [68, 38, 79, 116, 41, 91, 89, 87],
        "esperado": [
            214, 32, 110, 109, 116, 251, 159, 133, 226, 76, 193, 253, 168,
            73, 65, 197, 82, 72, 93, 68, 250, 55, 28, 202, 59, 77, 186, 27,
            97, 24, 48, 54, 106, 38, 82, 214, 222, 20, 20, 13, 251,
        ],
    },
    "T2": {
        "chave_ascii": [
            36, 64, 67, 42, 57, 41, 54, 67, 123, 52, 94, 100, 88, 78, 119,
            62, 72, 35, 87, 44, 98, 101, 47, 92, 39, 76, 50, 112, 77, 56,
            114, 59, 74, 89, 63, 120, 125, 66, 93, 64, 65, 96, 84, 33, 113,
            63, 105, 79, 96, 61, 110, 46, 76, 103, 109, 40, 51, 122, 56,
            64, 83, 91, 117, 93, 100, 89, 49, 107, 124, 37, 82, 73, 33, 77,
            80, 45, 40, 70, 116, 90, 108, 38, 94, 51, 58, 106, 110, 75, 60,
            84, 71, 54, 91, 53, 74, 119, 125,
        ],
        "esperado": [
            84, 179, 117, 15, 203, 82, 18, 217, 141, 197, 213, 126, 47,
            255, 83, 83, 99, 47, 120, 247, 192, 203, 33, 247, 220, 192,
            213, 82, 241, 248, 166, 142, 129, 105, 50, 227, 178, 74, 181,
            144, 94,
        ],
    },
    "T3": {
        "chave_ascii": [
            33, 77, 124, 55, 115, 93, 117, 94, 123, 68, 70, 106, 94, 63,
            56, 43, 102, 76, 58, 48, 90, 33, 42, 37, 49, 80, 95, 51, 66,
            125, 57, 109, 126, 86, 48, 64, 72, 94, 81, 102, 55, 121, 38,
            90, 52, 87, 98, 62, 107, 83, 94, 84, 60, 100, 46, 36, 46, 112,
            76, 64, 82, 124, 103, 41, 120, 41, 45, 54, 40, 69, 38, 104, 37,
            84, 45, 125, 40, 87, 37, 122, 123, 85, 57, 109, 90, 122, 56,
            126, 109, 56, 66, 102, 80, 33, 99, 38, 64, 107, 55, 73, 92, 53,
            73, 126, 84, 95, 118, 68, 33, 52, 65, 62, 124, 111, 79, 91,
            125, 51, 42, 84, 124, 36, 63, 101, 126, 48, 93, 86, 53, 38,
            121, 64, 114, 49, 88, 50, 107, 43, 64, 84, 93, 106, 63, 124,
            50, 124, 81, 37, 125, 82, 44, 68, 41, 85, 112, 92, 56, 103, 77,
            59, 87, 125, 124, 55, 101, 78, 70, 107, 94, 116, 46, 104, 47,
            106, 59, 54, 35, 121, 45, 33, 116, 53, 41, 92, 94, 76, 74, 91,
            55, 83, 60, 52, 65, 44, 102, 36, 75, 115, 49, 124, 38, 115, 88,
            33, 119, 42, 71, 40, 90, 64, 105, 62, 106, 69, 62, 54, 126, 93,
            111, 65, 53, 93, 107, 39, 46, 58, 111, 61, 55, 110, 57, 104,
            41, 36, 74, 95, 33, 97, 66, 123, 78, 45, 74, 98, 49, 77, 125,
            78, 122, 68, 92, 42, 104,
        ],
        "esperado": [
            192, 115, 138, 155, 179, 72, 115, 33, 116, 105, 228, 122, 36,
            92, 74, 122, 123, 245, 202, 209, 214, 199, 4, 191, 90, 96, 21,
            15, 190, 222, 47, 58, 192, 192, 43, 10, 166, 63, 58, 96, 230,
        ],
    },
}


def _formatar_gabarito(dados: bytes) -> str:
    """
    Mesmo formato usado no gabarito da disciplina para o "Texto Cript."
    (colchetes, números decimais separados por espaço -- sem vírgula).

    >>> _formatar_gabarito(bytes([214, 32, 110]))
    '[214 32 110]'
    """
    return "[" + " ".join(str(b) for b in dados) + "]"


def cifrar(mensagem: str, chave: str) -> None:
    """
    Mostra o mesmo resultado em TRÊS formas, porque cada uma serve pra
    comparar com uma coisa diferente:
      - Base64: é o que rc4.cifrar() devolve, e o que aparece em
        "[CIFRADO recebido] ..." no console do servidor;
      - decimal: é o formato do "Texto Cript." do gabarito da disciplina
        -- os MESMOS bytes, só decodificados de volta do Base64;
      - quadro completo: é o que procurar na vista ASCII do Wireshark.
    """
    cifrado_base64 = rc4.cifrar(mensagem, chave)
    bytes_crus = base64.b64decode(cifrado_base64)
    quadro = protocolo.empacotar(protocolo.TIPO_MENSAGEM, cifrado_base64)

    print("Base64 (rc4.cifrar() / console do servidor):")
    print(f"  {cifrado_base64!r}")
    print("\nMesmos bytes, em decimal (formato do gabarito da disciplina):")
    print(f"  {_formatar_gabarito(bytes_crus)}")
    print("\nQuadro completo (procure isto no Wireshark, vista ASCII):")
    print(f"  {quadro.decode('ascii')!r}")


def decifrar(capturado: str, chave: str) -> None:
    """
    Reaproveita o MESMO desempacotador que client.py/server.py usam, então
    aceita colar um ou vários quadros grudados, exatamente como saem do
    Wireshark -- não precisa cortar cabeçalho na mão.
    """
    bruto = capturado.strip().encode("ascii")
    desempacotador = protocolo.Desempacotador()

    try:
        quadros = desempacotador.alimentar(bruto)
    except protocolo.ErroProtocolo as erro:
        print(f"Cabeçalho não reconhecido -- colou o trecho certo, sem misturar")
        print(f"os dois sentidos do stream? Detalhe: {erro}")
        return

    if not quadros:
        print("Nenhum quadro COMPLETO nesse texto (faltou byte, ou não é um quadro).")
        return

    for i, quadro in enumerate(quadros, start=1):
        if quadro.texto is None:
            print(f"[{i}] quadro descartado -- payload não-ASCII: {quadro.erro}")
            continue

        if quadro.tipo == protocolo.TIPO_MENSAGEM:
            texto = rc4.decifrar(quadro.texto, chave)
            print(f"[{i}] tipo=M (mensagem cifrada)")
            print(f"     cifrado (Base64)  : {quadro.texto!r}")
            try:
                bytes_crus = base64.b64decode(quadro.texto, validate=True)
                print(f"     cifrado (decimal) : {_formatar_gabarito(bytes_crus)}")
            except binascii.Error:
                # Não é Base64 bem-formado -- provavelmente veio de outra
                # cifra, ou o trecho colado não é um payload RC4 de verdade.
                # rc4.decifrar() já é tolerante a isso (ver seu docstring);
                # aqui só avisamos que a forma decimal não pôde ser calculada.
                print("     cifrado (decimal) : (não é Base64 válido)")
            print(f"     decifrado         : {texto!r}")
        else:
            # Avisos de sistema (S) e controle (C) nunca são cifrados --
            # ver o contrato das cifras em cifras/sem_criptografia.py.
            print(f"[{i}] tipo={quadro.tipo} (nunca cifrado): {quadro.texto!r}")


def gabarito() -> None:
    """
    Roda os três casos de teste da disciplina (T1/T2/T3) contra o
    _rc4_xor() desta implementação e imprime, caso a caso, o que o
    gabarito espera lado a lado com o que foi obtido -- pensado pra ficar
    na tela durante a demonstração ao professor, sem precisar ler código
    de teste. A verificação equivalente como asserção automatizada é
    tests/test_rc4.py::teste_vetores_da_disciplina.
    """
    texto_plano = bytes(TEXTO_PLANO_ASCII)
    print(f"Texto plano (igual nos três casos): {texto_plano.decode('ascii')!r}\n")

    todos_bateram = True
    for nome, dados in VETORES_DA_DISCIPLINA.items():
        chave_bytes = bytes(dados["chave_ascii"])
        esperado = bytes(dados["esperado"])
        obtido = rc4._rc4_xor(texto_plano, chave_bytes)
        bateu = obtido == esperado
        todos_bateram = todos_bateram and bateu

        print(f"=== {nome} (chave de {len(chave_bytes)} bytes) ===")
        print(f"esperado (gabarito) : {_formatar_gabarito(esperado)}")
        print(f"obtido (esta impl.) : {_formatar_gabarito(obtido)}")
        print(f"resultado           : {'OK -- bytes identicos' if bateu else 'DIVERGIU'}\n")

    print("TODOS OS CASOS BATEM COM O GABARITO" if todos_bateram else "HÁ DIVERGÊNCIA -- revisar a implementação")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "gabarito":
        gabarito()
        return

    if len(sys.argv) != 4 or sys.argv[1] not in ("cifrar", "decifrar"):
        print(__doc__)
        sys.exit(1)

    _, modo, texto, chave = sys.argv
    if modo == "cifrar":
        cifrar(texto, chave)
    else:
        decifrar(texto, chave)


if __name__ == "__main__":
    main()
