from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import subprocess,threading,sys,os
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
import PyQt5
from hashlib import blake2b
from argon2 import PasswordHasher
import msvcrt,re,secrets,base64,requests

__all__=['Longinus']

class Longinus:
    TokenDB:dict=dict()
    #def Token_generator(self,length:int=32):
        #self.length=length
        #try:
        #if (length == 8 or length == 16 or  length== 32):
            #self.hash = blake2b(digest_size=self.length)
            #self.UserID=os.urandom(length)
            #self.Token=base64.b64encode(str({b'userid':self.UserID,b' timestamp':(str(datetime.now().timestamp()).split(".")[0]).encode(),b' external ip':re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', requests.get('http://ipconfig.kr').text)[1].encode(),b' internal ip':gethostbyname(gethostname()).encode()}).encode())
            #self.size = len(self.Token)
            #self.secrets_token = secrets.token_bytes(16)
            #self.Random_Token = bytearray()
            #for i in range(self.size):
                #self.Random_Token.append(self.Token[i]^self.secrets_token[i%16]),(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd)
            #self.hash.update(self.Random_Token)
            #self.Random_Token=self.hash.digest()
            #self.Token_secrets_token.setdefault(self.Random_Token,self.secrets_token)
        #else:
            #raise Exception("Token length input error: Token length must be 8 or 16 or 32")
        #except TypeError as e:
           #return e
        #return self.Random_Token
    def Token_generator(self,length:int=28,set_addres:str=None):
            self.length=length
            self.Usera_addres=set_addres
            if self.Usera_addres==None:
                raise Exception("User address cannot be None")
            #elif (length == 8 or length == 16 or  length== 32 and self.Usera_addres!=None):
            else:
                self.UserID=secrets.token_bytes(length);self.hash = blake2b(digest_size=self.length);self.hash.update(self.UserID);self.Token=self.hash.digest();self.Random_Token = bytearray()
                for i in range(self.hash.digest_size):
                    self.Random_Token.append(self.Token[i]^self.UserID[i%self.length])
                self.Token_data={'Time Stamp':(str(datetime.now().timestamp())),'User addres':self.Usera_addres,'login':False}
                self.TokenDB[bytes(self.Random_Token)]=self.Token_data
                return bytes(self.Random_Token),self.Token_data,self.TokenDB

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
                self.path=os.path.dirname( os.path.abspath( __file__ ) )
            else:
                raise Exception("Key length input error: Token length must be 1024 or 2048 or 4096 or 8192")
        except TypeError as e:
            raise Exception(str(e))
        return {"public_key":self.path+"\\"+"public_key.pem",".private_key":self.path+"\\"+"private_key.pem"}
    
    def token_verifier(self,Token:bytes):
        self.token=Token
        for k,v in self.TokenDB.items():
            if self.token ==k:
                return k,v
            else:
                return False
    
    def login_verifier(self,Token:bytes):
        self.token=Token
        temp,self.val=self.token_verifier(self.token)
        if self.val != False:
            if self.val['login']!=False:
                return True
            else:
                return False

    def file_checker(self,Route:str):
        self.Route=Route
        try:
            with open(self.Route,'r') as f:
                self.filedata=f.readlines()
                for line in self.filedata:
                    if ' | Token | ' in line:
                        return True
                    else:
                        return False
        except:
            return False

    def token_remover(self,Token):
        self.Token=Token
        del self.TokenDB[self.Token]
        return 'Done'

    def DB_saver(self,Token:bytes,Route:str):
        self.token=Token
        self.Route=Route
        key,self.val=self.token_verifier(self.token)
        if  self.file_checker(self.Route) == True:
            with open(self.Route,'a') as f:
                f.write('\n')
                f.write(str(key)+' | Token | '+str(self.val)+' | Token_data | ')
        else:
            with open(self.Route,'w') as f:
                f.write(str(key)+' | Token | '+str(self.val)+' | Token_data | ')
        
    def DB_loader(self,Route:str):
        self.Route=Route
        if  self.file_checker(self.Route) == True:
            with open(self.Route,'r') as f:
                self.rdata=f.readlines()
            return self.rdata

    def Token_loader(self,read_data):
        self.rdata=read_data
        for line in self.rdata:
            for num in range(len(line.split(' | '))):
                a=eval(line.split(' | ')[0]);b=eval(line.split(' | ')[2])
                self.TokenDB.setdefault(a,b)
        return self.TokenDB


    class authority_editor:
        def constructor(self,Token:bytes,rank:int):
            self.token=Token;self.rank=rank



    def bypass():
        pass