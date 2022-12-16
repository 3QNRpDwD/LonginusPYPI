import LonginusPYPI
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


class Server:
    LPL=LonginusPYPI.Longinus()
    Server_DB:dict=dict()
    Login_list:list=list()
    address=list()
    s=socket()
    def Index():
        pass
    def send():
        pass
    def recv(self):
        print("Waiting....")
        Server.s.bind(("0.0.0.0",9999))
        Server.s.listen(0)
        self.c,self.addr=Server.s.accept()
        self.Server.address.append(self.addr)
        print(self.Server.address.append(self.addr))
        self.recv_data=self.c.recv(2048)
        print(self.recv_data)
    def SignUp(self,UserName:str,User_pwrd:bytes):
        pass
    def ReSign(self,Token:bytes):
        pass
#############################################################################################################################################################################################################################
    def Login(self,UserName:str,User_pwrd:bytes):
        self.hash = blake2b(digest_size=32)
        self.UserName=UserName
        self.Userpwrd=User_pwrd
        if (" " not in self.UserName and "\r\n" not in self.UserName and "\n" not in self.UserName and "\t" not in self.UserName and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserName) is None):
            if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                self.hash.update(base64.b64encode(bytes(a ^ b for a, b in zip( self.Userpwrd, self.Token))))
                self.Userpwrd=PasswordHasher().hash(self.hash.digest())
                Server().Server_DB.setdefault(self.Token,{self.UserName:self.Userpwrd})
                return {self.Token:{self.UserName:self.Userpwrd}}
            else:
                print(User_pwrd.decode())
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")
#############################################################################################################################################################################################################################
    def Logout():
        pass
    def Rename():
        pass
    def Repwrd():
        pass
    def verify():
        pass
    def Decryption_Token(self,Token:bytes,IV_RSA:bytes,Keyfile:str):
        self.Token=Token
        self.iv_RSA=IV_RSA
        self.file=Keyfile
        if (self.Token==list and type(Token).__name__=="bytes" and [self.keys for self.keys in Server().Server_DB.keys() if self.keys in self.Token]):
            self.h = open(self.file, 'rb')  
            self.private_key = RSA.import_key(self.h.read())
            self.cipher_rsa = PKCS1_OAEP.new(self.private_key)
            self.h.close() 
            for self.t in self.Token:
                self.Token_decrypt = self.cipher_rsa.decrypt(self.t)
                self.iv=self.cipher_rsa.decrypt(self.iv_RSA)
                Server().Server_DB[self.Token_decrypt] = Server().Server_DB.pop(self.t)
                Server.LPL().Token_secrets_token.setdefault(self.Token_decrypt,self.iv)
                self.Token_decrypt=list()
                self.Token_decrypt.append(self.Token_decrypt)
            return self.Token_decrypt,self.iv
        elif Keyfile!=str:
            if Token in Server().Server_DB.keys():
                try:
                    self.h = open(self.file, 'rb')  
                    self.public_key = RSA.import_key(self.h.read())
                    self.cipher_rsa = PKCS1_OAEP.new(self.private_key)
                    self.h.close() 
                    self.Token_decrypt = self.cipher_rsa.decrypt(self.Token)
                    self.iv=self.cipher_rsa.decrypt(self.iv_RSA)
                    Server.LPL().Token_secrets_token.setdefault(self.Token_decrypt,self.iv)
                    Server().Server_DB[self.Token_decrypt] = Server().Server_DB.pop(self.Token)
                    return self.Token_decrypt,self.iv
                except FileNotFoundError:
                    raise Exception("The path to the specified key file could not be found!")
            else:
                raise  Exception("The token you entered is not stored in the database! Tokens to be encrypted must be in the database")
        else:
            raise  Exception("Could not find information about that token in the database data!")
    def Decryption_userdata(self,Token:bytes):
        self.keydata = Token
        if self.keydata in Server().Server_DB.keys():
            self.data=(str(Server().Server_DB[self.keydata])).encode()
            self.iv=Server.LPL().Token_secrets_token[self.keydata]
            self.cipher = AES.new(self.keydata, AES.MODE_CBC, self.iv)
            self.output= self.cipher.dencrypt(self.data)
            Server().Server_DB[self.keydata]=self.output
            return self.output
        else:
            raise  Exception("Could not find information about that token in the database data!")

Server().recv()



