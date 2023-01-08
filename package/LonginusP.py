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
    def __init__(self):
        self.TokenDB:dict=dict()

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
                self.Token_data={'Time Stamp':(str(datetime.now().timestamp())),'User addres':self.Usera_addres,'SignUp':False}
                self.TokenDB[bytes(self.Random_Token)]=self.Token_data
                return bytes(self.Random_Token),self.Token_data,self.TokenDB


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