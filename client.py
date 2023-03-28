from socket import socket, timeout


class HyperTextTransferProtocol:
    def __init__(self):
        self.hyper_text = b''

    def receive(self, max_recv_size=2048):
        while True:
            if b'\r\n\r\n' in self.hyper_text:
                break
            self.hyper_text += self.socket.recv(max_recv_size)
        return self.hyper_text

    def get(self, url: str, port: int = 80, params: dict = None):
        try:
            self.socket = socket()
            self.socket.connect((url, port))
            headers = self._prepare_request_headers('GET', url, params)
            self.socket.send(headers.encode())
            return self.receive()
        except (ConnectionRefusedError, timeout) as e:
            print(f'Request to server failed... Reason: {e}')
        finally:
            self.socket.close()

    def post(self):
        pass

    def _prepare_request_headers(self, method: str, url: str, params: dict):
        headers = {
            'Date': '',
            'User-Agent': 'longinuspypialpha',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'application/json',
        }
        if params is not None:
            if len(params) > 0:
                url += '?' + '&'.join([f'{key}={value}' for key, value in params.items()])
        return f'{method} {url} HTTP/1.1\r\n' + \
               '\r\n'.join([f'{key}: {value}' for key, value in headers.items()]) + \
               '\r\n\r\n'


while True:
    http = HyperTextTransferProtocol()
    user_input = input('Request : ')
    tokens = user_input.split(' ')
    params = None
    if tokens[0] == 'get':
        if len(tokens) >= 3:
            params = {}
            for token in tokens[2:]:
                param = token.split('=')
                if len(param) == 2:
                    params[param[0]] = param[1]
            response = None
            while response is None:
                try:
                    response = http.get(url=tokens[1], params=params) #get longinuspypialpha.kro.kr a=b c=d
                except:
                    print('try again...')
            print(response.decode())
        else:
            print('Invalid request.')
    else:
        print('Invalid request.')