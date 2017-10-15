from socket import socket, SO_REUSEADDR, SOL_SOCKET, AF_INET, SOCK_STREAM
from threading import Thread

import base64

# DES is a symmetric block cipher (shared secret key),
# with a key length of 56-bits. Published as the Federal Information
# Processing Standards (FIPS) 46 standard in 1977, DES was officially
# withdrawn in 2005 [although NIST has approved Triple DES (3DES)
# through 2030 for sensitive government information].
from Crypto.Cipher import DES


class Cipherer:
    def __init__(self, cipher_key):
        self.key = cipher_key
        self.cipher_obj = DES.new(cipher_key)
        self.BS = 16

    def decode(self, encrypted_text):
        # Return bytes of messages
        decryped = self.cipher_obj.decrypt(base64.b64decode(encrypted_text))
        return self._unpad(decryped)

    def encode(self, source_text):
        source_text = self._pad(source_text)
        return base64.b64encode(self.cipher_obj.encrypt(source_text))

    @staticmethod
    def _unpad(msg):
        return msg[:-ord(msg[len(msg) - 1:])]

    def _pad(self, msg):
        padding = (self.BS - (len(msg) % self.BS)) * chr(self.BS - len(msg) % self.BS)
        return msg + padding


key = "12345678"
cipherer = Cipherer(key)


def input_loop(tcp_socket):
    while True:
        outgoing = input('> ')

        if outgoing == "quit" or outgoing is None or len(outgoing) == 0:
            tcp_socket.close()
            break

        print("Sending:", outgoing)
        encrypted = cipherer.encode(outgoing)
        tcp_socket.send(encrypted)

    tcp_socket.close()
    exit(0)


def receive_loop(tcp_socket):
    while True:
        incoming = tcp_socket.recv(1024)
        if not incoming:
            tcp_socket.close()
            break

        decrypted = cipherer.decode(incoming).decode()
        print("Received:", incoming, "->", decrypted)

    tcp_socket.close()
    exit(0)


class ChatServer(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def print_info(self):
        print("You are listening on the IP address %s and port %s" % (self.ip, self.port))

    def start_server(self):
        address = (self.ip, self.port)
        self.tcp_socket = socket(AF_INET, SOCK_STREAM)
        self.tcp_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.tcp_socket.bind(address)
        self.tcp_socket.listen(1)

        tcp_client, source = self.tcp_socket.accept()
        print('Connection established from: ', source)

        return tcp_client


class ChatClient:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def print_info(self):
        print("You are connecting to the server at IP address %s through port %s" % (self.ip, self.port))

    def connect_to_server(self):
        ads = (self.ip, self.port)
        self.tcp_socket = socket(AF_INET, SOCK_STREAM)
        self.tcp_socket.connect(ads)
        print('Connecting to Server...')
        return self.tcp_socket


def main():
    print("Modes:\n[1] Server \n[2] Client")
    mode = input('Select mode:')
    hardcode_mode = True
    ip = None
    port = None

    if hardcode_mode:
        ip = "127.0.0.1"
        port = 56444

    if mode == "1":  # Server
        if not hardcode_mode:
            ip = "127.0.0.1"
            port = int(input('Please enter the port you wish to listen on: '))

        servcon = ChatServer(ip, port)
        servcon.print_info()

        connected_client = servcon.start_server()

        # TODO: kill those threads when the client disconnects
        Thread(target=receive_loop, args=[connected_client], daemon=True).start()
        input_loop(connected_client)

    elif mode == "2":
        if not hardcode_mode:
            ip = input('Please enter the IP address you want to connect to: ')
            port = int(input('Please enter the port you wish to connect to: '))

        chat_client = ChatClient(ip, port)
        chat_client.print_info()

        connected_client = chat_client.connect_to_server()

        Thread(target=receive_loop, args=[connected_client], daemon=True).start()
        input_loop(connected_client)

    else:
        print("Invalid input")


if __name__ == "__main__":
    main()
