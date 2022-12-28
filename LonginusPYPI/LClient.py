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
    def __init__(self,set_address:str,set_port:int):
        self.address=set_address;self.port=set_port;
        self.s=socket()
        try:
            self.s.connect((self.address,self.port))
        except:
            pass
        self.head=self.s.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        print(self.head)
        th=threading .Thread (target =self.recv_client(self.head) ).start ()
    def Index(self,Token:bytes):
        pass

    def send_client(self,data:bytes):
        ID,dw=self.user_injecter()
        self.Token=data
        self.data=self.SignUp(self.Token,ID,dw)
        self.body=self.Encryption(Token=self.Token,data=self.data)
        self.head=struct.pack("I",len(self.body))
        #print(len(self.body))
        self.send_data=self.head+self.body
        self.s.sendall(self.send_data)
        #print(self.send_data)
        a=input()
    
    def recv_client(self,head:int):
        while True:
            self.head=head
            self.recv_datas=bytearray()
            if self.head==256:
                self.recv_datas=self.Decryption_Token(self.s.recv(self.head))
                print('Token Issued : ',self.recv_datas)
                self.send_client(self.recv_datas)
                break
            else:
                for i in range(self.head/2048):
                    self.recv_datas.append(self.Decryption_Token(self.s.recv(2048)))
                    print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
            print('downloaded data : ',self.recv_datas)


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
                    self.login_data={self.UserID:self.temp_data}
                    return self.login_data
                else:
                    print(User_pwrd.decode())
                    raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
            else:
                raise  Exception("A user with the same name already exists. Please change the name.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

    def Encryption(self,Token,data:bytes):
        self.Token =Token
        self.data=str(data).encode()
        self.send_data=bytes
        recipient_key = RSA.import_key(open(r"C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\public_key.pem").read())
        session_key = self.Token

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(self.data)
        self.send_data
        self.send_data= enc_session_key+ cipher_aes.nonce+ tag+ ciphertext
        print(enc_session_key)#,'\n',cipher_aes.nonce,'\n',tag,'\n',ciphertext)
        return self.send_data


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

    #def Encryption_userdata(self,Token:bytes=None):
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
    
    #def Encryption_Token(self,Token:bytes,set_file:str='public_key.pem'):
        self.Token=Token
        self.file=set_file
        print(self.file)
        #if (self.Token==list and type(Token).__name__=="bytes" and self.keys in self.ClientDB.keys()):
        try:
            self.h = open(self.file, 'rb')  
            self.public_key = RSA.import_key(self.h.read())
            self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
            self.h.close() 
            self.Token_RSA = self.cipher_rsa.encrypt(self.t)
            self.ClientDB[self.Token_RSA] = self.ClientDB.pop(self.t)
            return self.Token_RSA
        except FileNotFoundError:
            raise Exception("The path to the specified key file could not be found!")
        #else:
            #raise  Exception("Could not find information about that token in the database data!")


    def Decryption_Token(self,Token:bytes,Keyfile:str=r"C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\public_key.pem"):
        self.Token=Token
        if type(self.Token).__name__=="bytes":
            self.public_key = RSA.import_key(open(Keyfile, 'rb')  .read())
            self.cipher_rsa = PKCS1_OAEP.new(self.public_key)
            self.Token_decrypt = self.cipher_rsa.decrypt(self.Token)
            return self.Token_decrypt

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