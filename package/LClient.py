from .LonginusP import *
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import subprocess,threading,sys,os
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
import PyQt5
from hashlib import blake2b
from argon2 import PasswordHasher
import msvcrt,re,secrets,secrets,base64,requests,hmac
import json
import struct

__all__=['Client']

class Client:
    L=Longinus()
    ClientDB:dict=dict()
    def __init__(self,set_addr:str='127.0.0.1',set_port:int=9997):
        self.addr=set_addr;self.port=set_port;self.recv_datas=bytes();self.SignUp_data=list;self.Cypherdata:bytes
        self.userid=str();self.pwrd=bytes();self.udata=bytes();self.head=bytes();self.rsa_keys:bytes=bytes()
        self.cipherdata=bytes();self.s=socket();self.token:bytes;self.atoken:bytes=bytes;self.rtoken:bytes
        #self.send_client(b'login')
        self.client_hello()
        self.recv_head()
        self.recv()
        self.json_decompress()
        self.pre_master_key_generator()
        self.client_key_exchange()
        # self.rsa_encode()
        # self.send_client(self.cipherdata)

    def Index(self,Token:bytes):
        pass

    def client_hello(self):
         self.s.connect((self.addr,self.port))
         self.rtoken=self.L.Random_Token_generator()
         self.jsobj={
            'content-type':'handshake', 
            'platform':'client',
            'version':'0.2.6',
            'addres':gethostbyname(gethostname()),
            'body':{'protocol':'client_hello',
                        'random_token':self.rtoken.decode(),
                        'random_token_length':len(self.rtoken),
                        'access_token':None,
                        'access_token_length':None,
                        'userid':None,
                        'userpw':None,
                        'master_secret':None
                        }
         }
         self.jsobj_dump= json.dumps(self.jsobj,indent=2)
         self.s.send(self.merge_data(self.jsobj_dump.encode()))

    def client_key_exchange(self):
        self.s=socket()
        self.s.connect((self.addr,self.port))
        self.Cypherdata=base64.b85encode(self.encryption_rsa(self.rsa_keys,self.pre_master_key))
        self.rtoken=self.L.Random_Token_generator()
        self.jsobj={
            'content-type':'handshake', 
            'platform':'client',
            'version':'0.2.6',
            'addres':gethostbyname(gethostname()),
            'body':{'protocol':'client_key_exchange',
                        'random_token':None,
                        'random_token_length':None,
                        'access_token':None,
                        'access_token_length':None,
                        'userid':None,
                        'userpw':None,
                        'master_secret':self.Cypherdata.decode()
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        self.s.send(self.merge_data(self.jsobj_dump.encode()))
        self.s.close()

    def merge_data(self,data:bytes):
        self.body=base64.b85encode(data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        return self.send_data

    def json_decompress(self):
        self.recv_datas=base64.b85decode(self.recv_datas).decode()
        self.jsobj = json.loads(self.recv_datas)
        self.server_version=self.jsobj["version"]
        self.token=self.jsobj['body']['random_token']
        self.atoken=self.jsobj['body']['access_token']
        self.platform=self.jsobj["platform"]
        self.protocol=self.jsobj['body']["protocol"]
        self.content_type=self.jsobj["content-type"]
        self.rsa_keys=self.jsobj['body']["public-key"]
        return


    def pre_master_key_generator(self):
        self.pre_master_key=self.L.master_key_generator(self.token.encode(),self.rtoken)
        return self.pre_master_key

    def send_client(self,data):
        self.s.sendall(self.merge_data(data))

    def recv_head(self):
        #try:
        self.head=self.s.recv(4)
        self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        return self.head
        #except:
            #print('An unexpected error occurred')

    def recv(self):
        self.recv_datas=bytes()
        if self.head<2048:
            self.recv_datas=self.s.recv(self.head)
            self.cipherdata=self.recv_datas
        elif self.head>=2048:
            self.recv_datas=bytearray()
            for i in range(int(self.head/2048)):
                self.recv_datas.append(self.s.recv(2048))
                print("  [ Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ]"+" [] Done... ] ")
            print("  [ Downloading "+str(self.addr)+"100 % ] [ Done... ] ",'\n')
            self.recv_datas=bytes(self.recv_datas)
        self.s.close()
        return self.recv_datas

    def SignUp(self):
        self.temp_data=bytearray()
        self.Userpwrd=self.pwrd.decode()
        if (" " not in self.userid and "\r\n" not in self.userid and "\n" not in self.userid and "\t" not in self.userid and re.search('[`~!@#$%^&*(),<.>/?]+', self.userid) is None):
            if len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd:
                self.SignUp_data=[{'userid':self.userid},{'userpw':self.Userpwrd}]
                return self.SignUp_data
            else:
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

    def ReSign(self,Token:bytes):
        pass

    def Login():
        pass

    def Logout():
        pass

    def Rename():
        pass

    def Repwrd():
        pass

    def emall_verify():
        pass

    # def Encryption(self,data:bytes):
    #     self.data=str(data).encode()
    #     self.send_data=bytes
    #     session_key = self.Token
    #     cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #     ciphertext, tag = cipher_aes.encrypt_and_digest(base64.b64encode(self.data))
    #     self.send_data= cipher_aes.nonce+ tag+ ciphertext
    #     return self.send_data

    def hmac_cipher(self,data):
        self.hmac_data=hmac.digest(self.master_key,data,blake2b)
        self.verified_data=data+self.hmac_data
        return self.verified_data


    def encryption_rsa(self,set_pul_key:str,data:bytes):
        public_key = RSA.import_key(set_pul_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.encrypt_data = cipher_rsa.encrypt(base64.b85encode(data))
        return self.encrypt_data

    def decryptio_rsa(self,set_prv_key:str,encrypt_data:bytes):
        private_key = RSA.import_key(set_prv_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        self.decrypt_data=base64.b85decode(cipher_rsa.decrypt(encrypt_data))
        return self.decrypt_data

    def Decryption_Token(self):
        private_key = RSA.import_key(open(self.set_keys['private_key']).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = base64.b64decode(cipher_rsa.decrypt(self.Token))
        return session_key

    def user_injecter(self):
        self.pwrd=bytes()
        self.userid=input("Please enter your name to sign up : ")
        self.input_num=0
        print("Please enter your password to sign up : ",end="",flush=True)
        while True:
            self.new_char=msvcrt.getch()
            if self.new_char==b'\r':
                break
            elif self.new_char==b'\b':
                if self.input_num < 1:
                    pass
                else:
                    msvcrt.putch(b'\b')
                    msvcrt.putch(b' ')
                    msvcrt.putch(b'\b')
                    self.pwrd+=self.new_char
                    self.input_num-=1
            else:
                print("*",end="", flush=True)
                self.pwrd+=self.new_char
                self.input_num+=1
        return self.userid,self.pwrd