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
import msvcrt,re,secrets,secrets,base64,requests,struct

__all__=['Server']

class Server:

    L= Longinus()
    Login_list:list=list()
    def __init__(self,set_addr:str="0.0.0.0",set_port:int=9997):
        self.s=socket()
        self.s.bind((set_addr,set_port))
        self.s.listen(0)
        while True:
            #try:
            self.address=list()
            self.head,self.c,self.addr=self.recv_head()
            self.address.append(self.addr)
            self.pul_key=self.recv_keys()
            self.Token,self.Token_data,self.Token_DB=self.L.Token_generator(length=32,set_addres=self.addr)
            self.Token_RSA=self.Encryption_token(self.Token,self.pul_key)
            self.send_server()
            print(self.Token)
            print(self.Token_data)
            self.head=self.c.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
            self.userdata=self.recv_server()
            self.userdata=self.Decryption(self.userdata)
            self.userdata=self.user_data_decompress(self.Token,self.userdata)
            self.userdata=self.SignUp(self.userdata[0],self.userdata[1])
            self.Server_DB:dict=dict()
            self.Server_DB[self.Token]=self.userdata
            print(self.Server_DB)
            self.saveing_all_data()
            #except:
                #print("unexpected error")
                #continue
    def Index():
        pass

    def send_server(self):
        self.c.sendall(self.merge_data())
        return 'done'

    def user_data_decompress(self,token,data):
        self.temp=data;self.Token=token
        self.temp=self.temp[self.Token]
        self.temp=eval(self.temp.decode())
        self.uid=self.temp[0];self.uwp=self.temp[1];self.uwp=self.uwp['userpw']
        self.temp0=bytearray()
        for i in range(len(self.uwp)):
            self.temp0.append(self.uwp[i]^self.Token[i%len(self.Token)])
        self.temp=self.temp[1];self.temp['userpw']=bytes(self.temp0)
        print([self.uid,self.temp])
        return [self.uid,self.temp]
        

    def recv_head(self):
        #try:
        while True:
            print('waiting for client...')
            self.c,self.addr=self.s.accept();
            self.head=self.c.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
            print('[Received from] : ',str(self.addr))
            return self.head,self.c,self.addr
        #except:
            #print('An unexpected error occurred')

    def merge_data(self):
        self.head=struct.pack("I",len(self.Token_RSA))
        self.send_data=self.head+self.Token_RSA
        print('send : ','\n')
        return self.send_data

    def recv_keys(self):
        while True:
            self.recv_datas=bytes()
            if self.head<2048:
                self.recv_datas=self.c.recv(self.head)
                self.recv_datas=base64.b64decode(self.recv_datas)
                return self.recv_datas
            elif self.head>=2048:
                self.recv_datas=bytearray()
                for i in range(int(self.head/2048)):
                    self.recv_datas.append(self.c.recv(2048))
                    print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
                self.recv_datas=base64.b64decode(bytes(self.recv_datas))
                return self.recv_datas

    def recv_server(self):
        while True:
            self.recv_datas=bytes()
            if self.head<2048:
                self.recv_datas=self.c.recv(self.head)
                self.recv_datas=self.recv_datas
                return self.recv_datas
            elif self.head>=2048:
                self.recv_datas=bytearray()
                for i in range(int(self.head/2048)):
                    self.recv_datas.append(self.c.recv(2048))
                    print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
                self.recv_datas=bytes(self.recv_datas)
                return self.recv_datas     
        #except:
            #print('An unexpected error occurred')

    def Decryption(self,data:bytes):
        self.data=data
        self.temp=list
        public_key = RSA.import_key(open(self.pul_key))
        n=public_key.size_in_bytes()
        nonce=self.data[n:n+16]
        tag=self.data[n+16:n+32]
        ciphertext =self.data[n+32:-1]+self.data[len(self.data)-1:]
        #print(enc_session_key,'\n',nonce,'\n',tag,'\n',ciphertext)
        #print(print(ciphertext+self.data[len(self.data)-1:]))
        # Decrypt the session key with the private RSA key
        session_key = self.Token
        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data


    def SignUp(self,UserID:dict,User_pwrd:dict):
        self.UserID=UserID['userid']
        self.Userpwrd=User_pwrd['userpw']
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                self.Userpwrd=self.L.pwd_hashing(base64.b64encode(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd))))
                self.login_data=[{'userid':self.UserID},{'userpw':self.Userpwrd}]
                return [{'userid':self.UserID},{'userpw':self.Userpwrd}]
            else:
                print(User_pwrd.decode())
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

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
                self.Server_DB.setdefault(self.Token,{self.UserName:self.Userpwrd})
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

    def token_remover(self,Token):
        self.Token=Token
        del self.Token_DB[self.Token]
        return 'done'

    def Encryption_token(self,Token:bytes,set_public_key:bytes):
        self.Token =Token
        public_key = RSA.import_key(set_public_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.Token_RSA = cipher_rsa.encrypt(base64.b64encode(self.Token))
        return self.Token_RSA

    def Decryption(self,data:bytes):
        self.data=data
        #print(self.data)
        self.temp=list
        nonce=self.data[:16]
        tag=self.data[16:32]
        ciphertext =self.data[32:-1]+self.data[len(self.data)-1:]
        #print(nonce,'\n',tag,'\n',ciphertext)
        session_key = self.Token
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = base64.b64decode(cipher_aes.decrypt_and_verify(ciphertext, tag))
        return {session_key:data}

    def saveing_all_data(self,Route=r'C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\package\LonginusPYPL\ServerDB.DB'):
        self.L.DB_saver(self.Token,Route)
        if  self.L.file_checker(Route) == True:
            with open(Route,'a') as f:
                f.write('\n')
                f.write(str(self.Token)+' | Token | '+str(self.userdata)+' | User_data | ')
        else:
            with open(Route,'w') as f:
                f.write(str(self.Token)+' | Token | '+str(self.userdata)+' | User_data | ')