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
    def __init__(self,set_address:str='127.0.0.1',set_port:int=9997):
        self.address=set_address;self.port=set_port;
        self.s=socket()
        self.s.connect((self.address,self.port))
        self.set_keys:dict=self.setting_keys()
        self.send_keys()
        self.Token=self.recv_client()
        self.uid,self.upw=self.user_injecter() 
        self.udata=self.SignUp(self.Token,self.uid,self.upw)
        self.udata=self.Encryption(self.udata)
        self.send_userdata(self.udata)
    def Index(self,Token:bytes):
        pass

    def send_keys(self):
        with open(self.set_keys['public_key'],'r') as kfc:
            self.body=base64.b64encode(kfc.read().encode())
        self.s.sendall(self.merge_data(self.body))

    def merge_data(self,data):
        self.body=data
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        return self.send_data

    def send_userdata(self,data):
        self.udata=data
        self.s.sendall(self.merge_data(self.udata))

    def recv_client(self):
        while True:
            self.head=self.s.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
            self.recv_datas=bytearray()
            if self.head==self.head:
                self.recv_datas=self.Decryption_Token(self.s.recv(self.head))
                print('Token Issued : ',self.recv_datas)
                #self.send_client(self.recv_datas)
                return self.recv_datas
            else:
                for i in range(int(self.head/2048)):
                    self.recv_datas.append(self.Decryption_Token(self.s.recv(2048)))
                    print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
                print('downloaded data : ',self.recv_datas)
                return self.recv_datas


    def SignUp(self,Token:bytes,UserID:str,User_pwrd:bytes):
        self.Token=Token
        self.UserID=UserID
        self.Userpwrd=User_pwrd
        self.temp_data=bytearray()
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if self.user_checker(UserID)==False:
                if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                    for i in range(len(self.Userpwrd)):
                        self.temp_data.append(self.Userpwrd[i]^self.Token[i%len(self.Token)])
                    self.login_data=[{'userid':self.UserID},{'userpw':bytes(self.temp_data)}]
                    return self.login_data
                else:
                    print(User_pwrd.decode())
                    raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
            else:
                raise  Exception("A user with the same name already exists. Please change the name.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")


    def setting_keys(self,len:int=2048):
        self.set_keys=self.L.Create_RSA_key()
        return self.set_keys

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

    
    def check_DB(self):
        if self.ClientDB==None:
            self.ClientDB.setdefault(self.user_injecter())
            return self.ClientDB
        else:
            return self.ClientDB

    def Encryption(self,data:bytes):
        self.data=str(data).encode()
        self.send_data=bytes
        session_key = self.Token
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(base64.b64encode(self.data))
        self.send_data= cipher_aes.nonce+ tag+ ciphertext
        return self.send_data

    def Decryption_Token(self,Token):
        self.Token=Token
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