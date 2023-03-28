import re
import socket
import threading
import requests


class HyperTextTransferProtocol:
    def __init__(self):
        self.head = bytes()
        self.recv_datas = bytes()
        self.s = socket.socket()

    def bind_address(self, address='0.0.0.0', port=80):
        req = requests.get("http://ipconfig.kr")
        ip = re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', req.text)[1]
        self.s.bind((address, port))
        print(f"[Server started on] ==> {ip}:{port}")

    def listen(self, limit=0):
        self.s.listen(limit)

    def accept_connection(self):
        global ip, col_ip, col_addr
        self.c, self.addr = self.s.accept()
        col_addr = '\033[33m' + f'{self.addr}' + '\033[0m'
        ip = str(self.addr).split("'")[1]
        col_ip = '(' + '\033[38;5;214m' + ip + '\033[0m' + ')'
        print('---------------------------------------------')
        print(f"[Connected with] ==> {col_addr}")

    def receive_data(self, MAX_RECV_SIZE=2048):
        self.recv_datas = b''
        while True:
            if b'\r\n\r\n' in self.recv_datas:
                break
            self.recv_datas += self.c.recv(MAX_RECV_SIZE)
            if b'GET' in self.recv_datas:
                print(f'[GET request from] ==> {col_addr}')
            return self.recv_datas

    def send_response(self, data):
        self.c.send(data)
        print(f'[Response sent to] ==> {col_addr}')
        self.c.close()
        print(f'[Disconnected from] ==> {col_addr}')


class PrepareHeader:
    def __init__(self, user_agent='127.0.0.1', body=None, status_code="HTTP/1.1 200 OK"):
        self.body = body
        self.string_header = status_code + '\r\n'
        self.default_header = {}
        for key, value in self.default_header.items():
            line = f'{key}:{value}'
            self.string_header += line + '\r\n'
        self.string_header += '\r\n'


def start_service():
    global http
    http = HyperTextTransferProtocol()
    http.bind_address()
    http.listen()
    threading.Thread(target=run_http).start()


def run_http():
    while True:
        http.accept_connection()
        data = http.receive_data()
        http.send_response(data)


if __name__ == '__main__':
    start_service()