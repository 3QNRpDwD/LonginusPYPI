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
import msvcrt,re,secrets,secrets,base64,requests
import json
import struct

__all__=['Client']

class Client:
    L=Longinus()
    ClientDB:dict=dict()
    def __init__(self,set_addr:str='127.0.0.1',set_port:int=9997):
        self.addr=set_addr;self.port=set_port;self.recv_datas=bytes();self.SignUp_data=list
        self.userid=str();self.pwrd=bytes();self.udata=bytes();self.head=bytes();self.rsa_keys=bytes
        self.cipherdata=bytes();self.s=socket()
        #self.send_client(b'login')
        self.recv_head()
        self.recv_keys()
        self.user_injecter()
        self.SignUp()
        self.rsa_encode()
        self.send_client(self.cipherdata)

    def Index(self,Token:bytes):
        pass

    # def send_keys(self):
    #     self.s=socket()
    #     self.s.connect((self.address,self.port))
    #     with open(self.set_keys['public_key'],'r') as kfc:
    #         self.body=base64.b64encode(kfc.read().encode())
    #     self.s.sendall(self.merge_data(self.body))

    def merge_data(self,data):
        self.body=data
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        return self.send_data

    def send_client(self,data):
        self.s.sendall(self.merge_data(data))

    def recv_head(self):
        #try:
        self.s.connect((self.addr,self.port))
        self.head=self.s.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        return self.head
        #except:
            #print('An unexpected error occurred')

    def recv_keys(self):
        self.recv_datas=bytearray()
        if self.head==self.head:
            self.rsa_keys=base64.b64decode(self.s.recv(self.head))
            return self.rsa_keys
        else:
            for i in range(int(self.head/2048)):
                self.recv_datas.append(self.s.recv(2048))
                print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
            print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
            self.rsa_keys=self.recv_datas
            return self.rsa_keys

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

    def token_verifier():
        pass

    def verify():
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

    def rsa_encode(self):
        public_key = RSA.import_key(self.rsa_keys)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.cipherdata = cipher_rsa.encrypt(base64.b64encode((str(self.SignUp_data).encode())))
        return self.cipherdata

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
Client()