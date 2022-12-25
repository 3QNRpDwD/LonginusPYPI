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
    RSAkey='public_key.pem' 
    def __init__(self,set_address:str,set_port:int):
        self.address=set_address;self.port=set_port;
        self.s=socket()
        try:
            self.s.connect((self.address,self.port))
        except:
            raise('Server did not respond')
        self.head=self.s.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        print('Received token from server')
        th=threading .Thread (target =self.recv_client(self.head) ).start ()
    def Index(self,Token:bytes):
        pass
            
    def send_client(self,data:bytes):
        self.body=data
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        self.s.sendall(self.send_data)
        print(self.send_data)
    
    def recv_client(self,head):
        while True:
            self.head=head
            self.recv_datas=bytearray()
            if self.head==32:
                self.recv_datas=self.s.recv(self.head)
                print('Token Issued : ',self.recv_datas)
                self.send_client(self.recv_datas)
                break
            elif self.head<1024:
                self.recv_datas=self.s.recv(self.head)
                print('downloaded data : ',self.recv_datas)
            else:
                for i in range(self.head/2048):
                    self.recv_datas.append(self.s.recv(2048))
                    print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
            print('downloaded data : ',self.recv_datas)
    def recv(self):
        pass
        

    def SignUp(self,UserID:str,User_pwrd:bytes):
        self.hash = blake2b(digest_size=32)
        self.UserID=UserID
        self.Userpwrd=User_pwrd
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if self.user_checker(UserID)==False:
                if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                    self.hash.update(base64.b64encode(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd))))
                    self.Userpwrd=PasswordHasher().hash(self.hash.digest())
                    self.login_data={self.UserID:self.Userpwrd}
                    return self.login_data
                else:
                    print(User_pwrd.decode())
                    raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
            else:
                raise  Exception("A user with the same name already exists. Please change the name.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

    def ReSign(self,Token:bytes):
        pass

    def Login():
        pass

    def Logout():
        pass

    def user_checker(self,UserID:str):
        self.UserID=UserID
        self.Userdata=self.ClientDB.values()
        if self.UserID in self.Userdata:
            return True
        else:
            return False

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

    def check_key(self):
        if self.RSAkey==None:
            self.RSAkey=self.L.Create_RSA_key()
            return self.RSAkey
        else:
            return self.RSAkey
    
    def check_DB(self):
        if self.ClientDB==None:
            self.ClientDB.setdefault(self.user_injecter())
            return self.ClientDB
        else:
            return self.ClientDB

    def Encryption_userdata(self,Token:bytes=None):
        self.keydata = Token
        cbytes = lambda x: str.encode(x) if type(x) == str else x
        if self.keydata in self.ClientDB.keys():
            self.data=(str(self.ClientDB[self.keydata])).encode()
            self.iv=self.L.Token_secrets_token[self.keydata]
            padding = 16-len(self.data)%16
            padding = cbytes(chr(padding)*padding)
            self.cipher = AES.new(self.keydata, AES.MODE_CBC, self.iv)
            self.output= self.cipher.encrypt(cbytes(self.data+padding))
            self.ClientDB[self.keydata]=self.output
            return self.output
        else:
            raise  Exception("Could not find information about that token in the database data!")
    
    def Encryption_Token(self,Token:bytes,set_file:str):
        self.Token=Token
        self.file=set_file
        print(self.file)
        if (self.Token==list and type(Token).__name__=="bytes" and self.keys in self.ClientDB.keys()):
            try:
                self.h = open(self.file, 'rb')  
                self.public_key = RSA.import_key(self.h.read())
                self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
                self.h.close() 
                for self.t in self.Token:
                    self.Token_RSA = self.cipher_rsa.encrypt(self.t)
                    self.iv_RSA = self.cipher_rsa.encrypt(self.L.Token_secrets_token[self.t])
                    self.ClientDB[self.Token_RSA] = self.ClientDB.pop(self.t)
                    self.Token_RSA=list()
                    self.Token_RSA.append(self.Token_RSA)
                return self.Token_RSA,self.iv_RSA
            except FileNotFoundError:
                raise Exception("The path to the specified key file could not be found!")
        else:
            raise  Exception("Could not find information about that token in the database data!")

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


Client('192.168.0.2',9997)