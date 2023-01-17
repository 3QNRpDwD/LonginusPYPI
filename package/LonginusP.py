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
import msvcrt,re,secrets,base64,requests,hmac


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

    def Access_Token_generator(self,length:int=16,set_addres:str=None,set_internal_ip=None):
            self.length=length
            self.Usera_addres=set_addres
            self.internal_ip=set_internal_ip
            self.UserID=secrets.token_bytes(length);self.hash = blake2b(digest_size=self.length);self.hash.update(self.UserID);self.Token=self.hash.digest();self.Access_Token = bytearray()
            self.Token=base64.b85encode(self.Token);self.UserID=base64.b85encode(self.UserID)
            for i in range(len(self.Token)):
                self.Access_Token.append(self.Token[i]^self.UserID[i%self.length])
            self.Access_Token=base64.b85encode(bytes(self.Access_Token))
            self.Token_data={'Time Stamp':(str(datetime.now().timestamp())),'User addres':self.Usera_addres,'internal_ip':self.internal_ip,'SignUp':False}
            self.TokenDB[self.Access_Token]=self.Token_data
            return self.Access_Token,self.Token_data

    def master_key_generator(self,client_token,server_token):
        self.stk=server_token;self.ctk=client_token;tmep1=None;tmep2=None;tmep3=None
        if (len(self.stk)==len(self.ctk)):
            self.master_key=self.cipher_generator(self.stk,self.ctk)
            return self.master_key
        
    def cipher_generator(self,temp1,temp2):
        self.cipher_temp1=bytes();self.cipher_temp2=bytes();
        self.cipher_temp1=bytes(a ^ b for a, b in zip(temp1,temp2))
        self.cipher_temp2=bytes(a ^ b for a, b in zip(self.cipher_temp1,temp2))
        self.cipher_temp1=bytes(a ^ b for a, b in zip(temp1,self.cipher_temp2))
        self.cipher_temp2=base64.b85encode(bytes(a ^ b for a, b in zip(self.cipher_temp2,self.cipher_temp1)))
        return self.cipher_temp2

    def token_login_activator(self,Token):
        self.token=Token
        self.TokenDB[self.token]['SignUp']=True
        return self.TokenDB[self.token],self.TokenDB

    def Token_filter(self,scan_list):
        self.scan_list=scan_list
        self.scan_temp=list()
        self.temp_data=dict()
        for n in self.scan_list:
            self.scan_temp.append(self.TokenDB[n]['Time Stamp'])
            self.temp_data[self.TokenDB[n]['Time Stamp']]=n
        self.result=self.temp_data.get(sorted(self.scan_temp)[0])
        return self.result
    
    def Token_User_address(self,Token,addr):
        self.Token=Token
        self.addr=addr
        self.temp=self.TokenDB[self.Token]['User addres']
        if self.addr==self.temp:
            return self.Token
        else:
            return False

    def token_address_explorer(self,addr):
        self.scan_list=list()
        for x,y in self.TokenDB.items():
            if y['User addres'] ==  addr:
                self.scan_list.append(x)
        if len(self.scan_list) >=2:
            return self.Token_filter(self.scan_list)
        else:
            return self.scan_list[0]
    
    def Token_User_login(self,Token):
        self.Token=Token
        if self.TokenDB[self.Token]['SignUp']!=False:
            return True
        else:
            return False

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

    def pwd_hashing(self,pwd):
        ph=PasswordHasher()
        while True:
            temp=ph.hash(pwd)
            if (ph.verify(temp,pwd)!=True and ph.check_needs_rehash(temp)!=False):
                continue
            break
        return temp

    def file_checker(self,Route:str):
        self.Route=Route
        try:
            with open(self.Route,'r') as f:
                self.filedata=f.readlines()
                for line in self.filedata:
                    if ' | Token_data | ' in line:
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
        if  self.file_checker(self.Route) == True:
            with open(self.Route,'a') as f:
                f.write('\n')
                f.write(str(self.token)+' | Token | '+str(self.Token_data)+' | Token_data | ')
        else:
            with open(self.Route,'w') as f:
                f.write(str(self.token)+' | Token | '+str(self.Token_data)+' | Token_data | ')
        
    def Token_DB_loader(self,Route:str):
        self.Route=Route
        if  self.file_checker(self.Route) == True:
            with open(self.Route,'r') as f:
                self.rdata=f.readlines()
                self.rdata=self.Token_loader(self.rdata)
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