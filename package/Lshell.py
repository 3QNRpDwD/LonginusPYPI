import re,requests,struct
from socket import *

__all__=['shell']

class shell:
    def __init__(self):
        self.cmd=str()
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '
        self.head2=bytes();self.recv_datas2=bytes();self.result=''

    def launcher(self):
        while True:
            try:
                self.cmd=input(self.text)
                if self.cmd!='^C':
                    self.send_cmd()
                    self.recv_head2()
                    self.recv_result()
                    if len(self.result)==0:
                        print(' [ Command not found for ] : '+self.cmd.decode())
                    else:
                        print(self.result)
            except Exception as e:
                print(e)
                continue

    def recv_head2(self):
        self.head2=self.s.recv(4);self.head2=int(str(struct.unpack("I",self.head2)).split(',')[0].split('(')[1])
        return self.head2

    def recv_result(self):
        if self.head2<=2048:
            self.result=self.s.recv(self.head2)
            self.result=self.result.decode()
            self.s.close()
            return self.result
        elif self.head2>=2048:
            self.recv_datas2=bytes()
            for i in range(int(self.head2/2048)):
                self.recv_datas2+=self.s.recv(2048)
            self.recv_datas2=bytes(self.recv_datas2)
            self.result=self.recv_datas2.decode()
            self.s.close()
            return self.result

    def send_cmd(self):
        self.s=socket()
        self.cmd=self.cmd.encode()
        self.s.connect(('127.0.0.1',9998))
        self.head2=struct.pack("I",len(self.cmd))
        self.send_data=self.head2+self.cmd
        self.s.send(self.send_data)
