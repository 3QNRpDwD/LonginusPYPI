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
                #self.Random_Token.append(self.Token[i]^self.secrets_token[i%16])
            #self.hash.update(self.Random_Token)
            #self.Random_Token=self.hash.digest()
            #self.Token_secrets_token.setdefault(self.Random_Token,self.secrets_token)
        #else:
            #raise Exception("Token length input error: Token length must be 8 or 16 or 32")
        #except TypeError as e:
           #return e
        #return self.Random_Token
    def Token_generator(self,length:int=32,set_data:str=None):
            self.length=length
            #try:
            if (length == 8 or length == 16 or  length== 32 and set_data==None):
                self.UserID=secrets.token_bytes(length);self.hash = blake2b(digest_size=self.length);self.hash.update(self.UserID);self.Token=self.hash.digest();self.Random_Token = bytearray();self.TokenDB:dict=dict()
                for i in range(self.hash.digest_size):
                    self.Random_Token.append(self.Token[i]^self.UserID[i%self.length])
                self.Token_data={'Time Stamp':(str(datetime.now().timestamp()).split(".")[0]),'User ID':self.UserID,'login permission':False}
            elif (length == 8 or length == 16 or  length== 32 and set_data!=None):
                self.UserID=secrets.token_bytes(length);self.hash = blake2b(digest_size=self.length);self.hash.update(self.UserID);self.Token=self.hash.digest();self.Random_Token = bytearray();self.TokenDB:dict=dict()
                for i in range(self.hash.digest_size):
                    self.Random_Token.append(self.Token[i]^self.UserID[i%self.length])
                self.Token_data={'Time Stamp':(str(datetime.now().timestamp())),'User ID':self.UserID,'User addres':set_data,'login permission':False}
            else:
                raise Exception("Token length input error: Token length must be 8 or 16 or 32")
            #except TypeError as e:
            #return e
            return bytes(self.Random_Token),self.Token_data

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

    class authority_editor:
        def constructor(self,data,rank:int,mod:str):
            self.data=data
            self.rank=rank
            self.mod=mod
            #try:
            if rank<0:
                raise  Exception("Privilege rank cannot be negative. Double check the rank factor.")
            else:
                if self.mod=="overwrite" and len( self.authority_list)!=0:
                    if type(self.data).__name__=='list':
                        self.authority_list=dict.fromkeys(self.data,rank)
                    else:
                        self.authority_list={self.data:rank}
                elif self.mod=="add":
                    if type(self.data).__name__=='list':
                        for n in data:
                            self.authority_list[n]=rank
                    else:
                        self.authority_list[self.data]=rank
                elif self.mod!="add" and self.mod!="overwrite":
                    raise  Exception("There are two permission creation modes: add and overwrite. Check the mode argument.")
                elif self.mod=="overwrite" and len( self.authority_list)==0:
                    raise  Exception("f author_list is not empty, overwrite mode is enabled. Check the mode arguments again.")
        #except TypeError as e:
               # return e
            return  self.authority_list
        def Deleter(self,data,rank:int,mod:str):
            self.data=data
            self.rank=rank
            self.mod=mod
            try:
                if self.mod=="all":
                    self.authority_list.clear()
                    return  self.authority_list
                elif self.mod=="rank":
                    if type(self.rank).__name__!='list':
                        if self.rank<0:  
                           raise  Exception("Privilege rank cannot be negative. Double check the rank factor.")
                        for k,v in  self.authority_list.copy().items():
                            if self.rank in self.authority_list.values():
                                if self.rank==v:
                                    del self.authority_list[k]
                    else:
                        for r in self.rank:
                            for k,v in  self.authority_list.copy().items():
                                if r in self.authority_list.values():
                                    if r==v:
                                        del self.authority_list[k]
                elif self.mod=="data":
                    if type(self.data).__name__!='list':
                        for k,v in  self.authority_list.copy().items():
                            if self.data in self.authority_list.keys():
                                if self.data==k:
                                    del self.authority_list[k]
                    else:
                        for d in self.data:
                            for k,v in  self.authority_list.copy().items():
                                if d in self.authority_list.keys():
                                    if d==k:
                                        del self.authority_list[k]
            except TypeError as e:
                return e
            return  self.authority_list

    def bypass():
        pass