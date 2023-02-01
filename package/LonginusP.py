from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import os
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
from hashlib import blake2b
from argon2 import PasswordHasher
import secrets,base64


__all__=['Longinus']

class Longinus:
    def __init__(self):
        self.TokenDB:dict=dict()

    def Random_Token_generator(self,length:int=16):
            self.length=length
            self.UserID=secrets.token_bytes(length);self.hash = blake2b(digest_size=self.length);self.hash.update(self.UserID);self.Token=self.hash.digest();self.Random_Token = bytearray()
            self.Token=base64.b85encode(self.Token);self.UserID=base64.b85encode(self.UserID)
            for i in range(len(self.Token)):
                self.Random_Token.append((self.Token[i]^self.UserID[i%self.length]))
            self.Random_Token=base64.b85encode(bytes(self.Random_Token))
            return self.Random_Token

    def master_key_generator(self,client_token,server_token):
        self.stk=self.Random_Token_generator();self.ctk=self.Random_Token_generator()
        if (len(self.stk)==len(self.ctk)):
            self.master_key=self.cipher_generator(self.stk,self.ctk)
            return self.master_key
        
    def cipher_generator(self,temp1,temp2):
        self.cipher_temp1=bytes(a ^ b for a, b in zip(temp1,temp2))
        self.cipher_temp2=bytes(a ^ b for a, b in zip(self.cipher_temp1,temp2))
        self.cipher_temp1=bytes(a ^ b for a, b in zip(temp1,self.cipher_temp2))
        self.cipher_temp2=base64.b85encode(bytes(a ^ b for a, b in zip(self.cipher_temp2,self.cipher_temp1)))
        return self.cipher_temp2

    def Create_RSA_key(self,length:int=2048):  
        self.length=length
        try:
            if (length == 1024 or length == 2048 or  length== 4096 or  length==8192):
                self.key = RSA.generate(length)
                self.private_key = self.key.export_key()
                self.file_out = open("private_key.pem", "wb")
                self.file_out.write(self.private_key)
                self.file_out.close()
                self.public_key = self.key.publickey().export_key()
                self.file_out = open("public_key.pem", "wb")
                self.file_out.write(self.public_key)
                self.file_out.close()
                #self.path=os.path.dirname( os.path.abspath( __file__ ) )
                self.path=os.getcwd()
            else:
                raise Exception("Key length input error: Token length must be 1024 or 2048 or 4096 or 8192")
        except TypeError as e:
            raise Exception(str(e))
        return {"private_key":self.path+"\\"+"private_key.pem","public_key":self.path+"\\"+"public_key.pem"}
