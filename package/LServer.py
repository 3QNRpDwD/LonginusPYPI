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
from multiprocessing import Process

__all__=['Server']

class Server:

    L= Longinus()
    def __init__(self):
        self.Login_list:list=list();self.path:str=r'C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\package\LonginusPYPL';self.set_port:int=9997;self.set_addr:str='0.0.0.0';self.s=socket();self.ip:str=str()
        self.Token:bytes=bytes();self.Token_data:dict=dict();self.Token_DB:dict=dict();self.rdata:str='';self.platform:str='shell'
        self.head='';self.c='';self.addr='';self.Token_RSA:bytes=bytes();self.address=list();self.sessions:list=list()
        self.pul_key:bytes=bytes();self.userdata:bytes=bytes();self.Server_DB:dict=dict();self.new_session:dict=dict()

    def start_server(self):
            self.req = requests.get("http://ipconfig.kr")
            self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
            self.text='[ Server@'+self.req+' ~]$ '
            self.s.bind((self.set_addr,self.set_port))
            self.s.listen(0)
            print(' [ Server started at : '+self.req+' ] ')
            while True:
                #try:
                self.head,self.c,self.addr=self.recv_head()
                self.address.append(self.addr)
                self.pul_key=self.recv_keys()
                self.Token,self.Token_data,self.Token_DB=self.L.Token_generator(length=32,set_addres=self.addr)
                self.Token_RSA=self.Encryption_token(self.Token,self.pul_key)
                self.send_server(self.Token_RSA)
                print('  [ Send | Token ] : ',self.Token)
                self.head=self.c.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
                self.recv_server(set_head=self.head);self.Decryption(self.userdata,self.addr)
                self.user_data_decompress(self.Token,self.userdata);self.SignUp(self.userdata[0],self.userdata[1])
                self.session_classifier()
                self.Server_DB:dict=dict();self.Server_DB[self.Token]=self.userdata
                #print('  [ Server | database ] : ',self.sessions,'\n')
                self.saveing_all_data()
                self.reset_server()
                #except Exception as e :
                    #print(e)

    def login_checker(self):
        if self.recv_datas:
            pass

    def session_classifier(self):
        userid=self.userdata[0]['userid']
        if (userid=='Guest' or userid=='guest' or userid=='__Guest__' or userid=='__guest__'):
            self.guest_session_creator()
        elif (userid=='Admin' or userid=='admin' or userid=='__Admin__' or userid=='__admin__' or userid=='__administrator__'or userid=='administrator'or userid=='Administrator'or userid=='__Administrator__'):
            self.admin_session_creator()
        else:
            self.session_creator()
        return userid

    def admin_session_creator(self):
        self.Token,self.Token_data,self.Token_DB=self.L.Token_generator(length=32,set_addres=self.addr)
        if (self.ip=='127.0.0.1' and self.platform=='shell'):
            self.Token_data['SignUp']=True
            self.new_session={self.Token:{'user_id':self.userdata[0]['userid'],'user_pw':self.userdata[1]['userpw'],'permission_lv':0,'class':'__administrator__'}}
            self.new_session[self.Token].update(self.Token_data)
            self.sessions.append(self.new_session)
            print(self.sessions)
        return self.new_session
    
    def session_creator(self):
        self.Token,self.Token_data,self.Token_DB=self.L.Token_generator(length=32,set_addres=self.ip)
        if (self.ip!='127.0.0.1' and self.platform=='client'):
            self.Token_data['SignUp']=True
            self.new_session={self.Token:{'user_id':self.userdata[0]['userid'],'user_pw':self.userdata[1]['userpw'],'permission_lv':1,'class':'__user__'}}.update(self.Token_data)
            self.sessions.append(self.new_session)
        print(self.sessions)
        return self.new_session


    def guest_session_creator(self):
        self.Token,self.Token_data,self.Token_DB=self.L.Token_generator(length=32,set_addres=self.addr)
        if (self.ip=='127.0.0.1' and self.platform=='client'):
            self.Token_data['SignUp']=True
            self.new_session={self.Token:{'user_id':self.userdata[0]['userid'],'permission_lv':1,'class':'__guest__'}}.update(self.Token_data)
            self.sessions.append(self.new_session)
        print(self.sessions)
        return self.new_session

    def reset_server(self):
        self.rdata:str=''
        self.head='';self.Token_RSA:bytes=bytes();
        self.pul_key:bytes=bytes();self.userdata:bytes=bytes()

    def close_server(self):
        pass

    def send_server(self,data):
        self.c.sendall(self.merge_data(data))
        return 'done'

    def user_data_decompress(self,token,data):
        self.temp=data;self.Token=token
        self.temp=eval(self.temp.decode())
        self.uid=self.temp[0];self.uwp=self.temp[1];self.uwp=self.uwp['userpw']
        self.temp0=bytearray()
        for i in range(len(self.uwp)):
            self.temp0.append(self.uwp[i]^self.Token[i%len(self.Token)])
        self.temp=self.temp[1];self.temp['userpw']=bytes(self.temp0)
        self.userdata=[self.uid,self.temp]
        #print([self.uid,self.temp])
        return [self.uid,self.temp]
        
    def variable_indicator(self):
        pass

    def recv_head(self):
        #try:
        while True:
            self.c,self.addr=self.s.accept();
            self.head=self.c.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
            print('  [ Received | From ] : ',str(self.addr))
            self.ip=str(self.addr).split("'")[1]
            return self.head,self.c,self.addr
        #except:
            #print('An unexpected error occurred')

    def merge_data(self,data):
        self.head=struct.pack("I",len(data))
        self.send_data=self.head+data
        return self.send_data

    def recv_keys(self):
        while True:
            self.recv_datas=bytes()
            if self.head<2048:
                self.recv_datas=self.c.recv(self.head)
                self.recv_datas=base64.b64decode(self.recv_datas)
            elif self.head>=2048:
                self.recv_datas=bytearray()
                for i in range(int(self.head/2048)):
                    self.recv_datas.append(self.c.recv(2048))
                    print("  [ Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ] "+" [] Done... ] ")
                print("  [ Downloading "+str(self.addr)+"100 % ] [ Done... ]",'\n')
                self.recv_datas=base64.b64decode(bytes(self.recv_datas))
            print("  [ Received | Key ] ")
            return self.recv_datas

    def recv_server(self,set_head):
        while True:
            self.head=set_head
            self.recv_datas=bytes()
            if self.head<2048:
                self.recv_datas=self.c.recv(self.head)
                self.recv_datas=self.recv_datas
            elif self.head>=2048:
                self.recv_datas=bytearray()
                for i in range(int(self.head/2048)):
                    self.recv_datas.append(self.c.recv(2048))
                    print("  [ Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ]"+" [] Done... ] ")
                print("  [ Downloading "+str(self.addr)+"100 % ] [ Done... ] ",'\n')
                self.recv_datas=bytes(self.recv_datas)
            print("  [ Received | Data ] : ",self.recv_datas)
            self.userdata=self.recv_datas
            return self.recv_datas     
        #except:
            #print('An unexpected error occurred')


    def SignUp(self,UserID:str,User_pwrd:bytes):
        self.UserID=UserID['userid']
        self.Userpwrd=User_pwrd['userpw']
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if (len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode()):
                self.Userpwrd=self.L.pwd_hashing(base64.b64encode(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd))))
                self.login_data=[{'userid':self.UserID},{'userpw':self.Userpwrd}]
                self.userdata=self.login_data
                return self.login_data
            else:
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

    def ReSign(self,Token:bytes):
        pass
#############################################################################################################################################################################################################################
    def Login(self,UserName:str,User_pwrd:bytes):
        self.UserName=UserName
        self.Userpwrd=User_pwrd
        if (" " not in self.UserName and "\r\n" not in self.UserName and "\n" not in self.UserName and "\t" not in self.UserName and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserName) is None):
            if (len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode()):
                if PasswordHasher.verify(self.login_data['Userpw'],self.Userpwrd)==True:
                    self.Server_DB.setdefault(self.Token,{self.UserName:self.Userpwrd}) 
                    return {self.Token:{self.UserName:self.Userpwrd}}
            else:
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

    def Decryption(self,set_data:bytes,set_addr):
        self.data=set_data
        self.temp=list
        nonce=self.data[:16]
        tag=self.data[16:32]
        ciphertext =self.data[32:-1]+self.data[len(self.data)-1:]
        session_key = self.L.token_address_explorer(set_addr)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = base64.b64decode(cipher_aes.decrypt_and_verify(ciphertext, tag))
        self.userdata=data
        return data

    def Server_DB_checker(self):
        try:
            with open(self.path+'\\ServerDB.DB','r') as f:
                self.filedata=f.readlines()
                for line in self.filedata:
                    if ' | Sessions_data | ' in line:
                        return True
                    else:
                        return False
        except:
            return False

    def Server_DB_loader(self):
        if  self.Server_DB_checker() == True:
            with open(self.path+'\\SessionsDB.DB','r') as f:
                self.rdata=f.readlines()
                self.rdata=self.User_data_loader(self.rdata)
            return self.rdata

    def User_data_loader(self,rdata):
        self.rdata=rdata
        for line in self.rdata:
            for num in range(len(line.split(' | '))):
                a=eval(line.split(' | ')[0]);b=eval(line.split(' | ')[2])
                self.Server_DB.setdefault(a,b)
        return self.Server_DB

    def saveing_all_data(self):
        if  self.Server_DB_checker() == True:
            with open(self.path+'\\SessionDB.DB','a') as f:
                f.write('\n')
                f.write(str(self.sessions)+' | Sessions_data | ')
                print('done')
        else:
            with open(self.path+'\\SessionDB.DB','w') as f:
                f.write(str(self.sessions)+' | Sessions_data | ')

    def server_exit(self):
        sys.exit(self.text)