import threading
import socket

host = "127.0.0.1" # Atualizar IP para o da máquina HOST
port = 64146

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
nicknames = []

def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024)
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f"{nickname} saiu do chat ;-;".encode("utf-8"))
            nicknames.remove(nickname)
            break


def receive():
    while True:
        try:
            client, address = server.accept()
            print(f"Conectado com {str(address)}")

            client.send("NICK".encode("utf-8"))
            nickname = client.recv(1024).decode("utf-8")
            nicknames.append(nickname)
            clients.append(client)

            print(f"Apelido do cliente é {nickname}")
            broadcast(f"{nickname} entrou no chat :D".encode("utf-8"))
            client.send("Conectado com o servidor".encode("utf-8"))

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
        except:
            break

print("Servidor está online...")

receive()