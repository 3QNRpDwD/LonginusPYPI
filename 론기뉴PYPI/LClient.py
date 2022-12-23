from LonginusP import *
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
   # def __init__():
        #pass
    def Index(self,Token:bytes):
        pass
    
    def send(self,set_address:str,set_port:int,Token:bytes):
        self.s=socket()
        self.address=set_address
        self.port=set_port
        self.Token=Token
        self.msg=bytearray()
        self.s.connect(("192.168.0.2",9997))
        self.Encryption_userdata(self.Token)
        self.temp={self.Encryption_userdata(self.Token):self.Encryption_Token(self.Token)}
        print(str(self.temp.keys())+"\n"+str(self.temp.values()))
        self.body=json.dump(self.temp)
        self.head=len(self.jwt)
        self.msg+=bytearray(self.head.to_bytes(2, byteorder="big"))
        self.msg+=bytes(self.body)
        self.s.sendall(self.msg)
        return self.msg,self.body

    def recv():
        pass

    def SignUp(self,UserID:str,User_pwrd:bytes):
        self.hash = blake2b(digest_size=32)
        self.UserID=UserID
        self.Userpwrd=User_pwrd
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if self.user_checker(UserID)==False:
                if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                    self.Token=self.L.Token_generator(32)
                    self.hash.update(base64.b64encode(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd))))
                    self.Userpwrd=PasswordHasher().hash(self.hash.digest())
                    self.ClientDB[self.Token]={self.UserID:self.Userpwrd}
                    #Client().Encryption_userdata(self.Token)
                    return self.Token
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

    def Encryption_userdata(self,Token:bytes=L.Token_generator()):
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
    
    def Encryption_Token(self,Token:bytes=L.Token_generator(),set_file:str='public_key.pem'):
        self.Token=Token
        self.file=set_file
        print(self.file)
        if (self.Token==list and type(Token).__name__=="bytes" and [self.keys for self.keys in self.ClientDB.keys() if self.keys in self.Token]):
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
        elif self.file!=str:
            if Token in self.ClientDB.keys():
                try:
                    self.h = open(self.file, 'rb')  
                    self.public_key = RSA.import_key(self.h.read())
                    self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
                    self.h.close() 
                    self.Token_RSA = self.cipher_rsa.encrypt(self.Token)
                    self.iv_RSA = self.cipher_rsa.encrypt(self.L.Token_secrets_token[self.Token])
                    self.ClientDB[self.Token_RSA] = self.ClientDB.pop(self.Token)
                    return self.Token_RSA,self.iv_RSA
                except FileNotFoundError:
                    raise Exception("The path to the specified key file could not be found!")
            else:
                raise  Exception("The token you entered is not stored in the database! Tokens to be encrypted must be in the database")
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
        print(self.userid,self.pwrd)
        self.token=self.SignUp(self.userid,self.pwrd)
        self.d2 =threading .Thread (target =self.send("localhost",9997,self.token)).start ()#line:394
        return self.userid,self.pwrd

print(Client().check_key())
print(Client().user_injecter())