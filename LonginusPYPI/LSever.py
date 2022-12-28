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
    Server_DB:dict=dict()
    Token_DB:dict=dict()
    Login_list:list=list()
    address=list()
    def __init__(self,set_addr:str="0.0.0.0",set_port:int=9997):
        self.s=socket()
        self.s.bind((set_addr,set_port))
        self.s.listen(0)
        th=threading .Thread (target =self.send_Token() ).start ()

    def Index():
        pass


    def send_Token(self):
        #try:
        while True:
            print('waiting for client...')
            self.c,self.addr=self.s.accept()
            print(str(self.addr)+' : user connected')
            self.body,self.Token_data,self.Token_DB=self.L.Token_generator(set_addres=self.addr)
            self.c.sendall(self.merge_data(self.body))
            th2=threading .Thread (target =self.recv_server( )).start ()
        #except:
            #print('An unexpected error occurred')

    def merge_data(self,data):
        self.body=self.Encryption_Token(Token=data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        return self.send_data

    def recv_server(self):
        #try:
            while True:
                self.recv_datas=bytes()
                self.head=self.c.recv(4);self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
                if self.hea>1024:
                    self.recv_datas=self.c.recv(self.head)
                    self.recv_datas=self.Decryption(self.recv_datas)
                    break
                elif self.head<=1024:
                    self.recv_datas=bytearray()
                    self.de_data=bytearray
                    for i in range(self.head/2048):
                        self.recv_datas.append(self.c.recv(2048))
                        print("Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                    print("Downloading "+str(self.addr)+" Data... : "+"100 % Done...")
                    for u in self.recv_datas:
                        self.de_datas.append(self.Decryption(i))
                        print("Decrypting "+str(u)+" : "+str(2048*i/self.head*100)+" %"+" Done...")
                    print("Decrypting "+str(u)+" Data... : "+"100 % Done...")      
        #except:
            #print('An unexpected error occurred')

    def Decryption(self,data:bytes,set_private_key:str=r"C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\private_key.pem"):
        self.data=data
        self.temp=list
        private_key = RSA.import_key(open(set_private_key).read())
        n=private_key.size_in_bytes()
        enc_session_key=self.data[:n]
        nonce=self.data[n:n+16]
        tag=self.data[n+16:n+32]
        ciphertext =self.data[n+32:-1]+self.data[len(self.data)-1:]
        #print(enc_session_key,'\n',nonce,'\n',tag,'\n',ciphertext)
        #print(print(ciphertext+self.data[len(self.data)-1:]))
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        if self.L.token_verifier(session_key)!=False:
            # Decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
            return data
        else:
            self.L.token_remover(session_key)
            self.token_remover(session_key)
            return 'abnormal token'


    def SignUp(self,UserID:str,User_pwrd:bytes):
        self.UserID=UserID
        self.Userpwrd=User_pwrd
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if self.user_checker(UserID)==False:
                if len( self.Userpwrd.decode()) > 8 and re.search('[0-9]+', self.Userpwrd.decode()) is not None and re.search('[a-zA-Z]+', self.Userpwrd.decode()) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd.decode()) is not None and " " not in self.Userpwrd.decode() :
                    self.Userpwrd=base64.b64encode(bytes(a ^ b for a, b in zip( self.Token,self.Userpwrd)))
                    self.login_data={self.UserID:self.Userpwrd}
                    return self.login_data
                else:
                    print(User_pwrd.decode())
                    raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
            else:
                raise  Exception("A user with the same name already exists. Please change the name.")
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

    def Encryption_Token(self,Token:bytes,set_private_key:str=r"C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\private_key.pem"):
        self.Token=Token
        if self.L.token_verifier(self.Token)!=False:
            self.private_key = RSA.import_key(open(set_private_key, 'rb').read())
            self.cipher_rsa = PKCS1_OAEP.new(self.private_key)
            self.Token_RSA = self.cipher_rsa.encrypt(self.Token)
            return self.Token_RSA
        else:
            raise  Exception("Could not find information about that token in the database data!")


    #def Encryption_userdata(self,Token:bytes):
        #self.keydata = Token
        #cbytes = lambda x: str.encode(x) if type(x) == str else x
        #if self.keydata in self.ClientDB.keys():
            #self.data=(str(self.ClientDB[self.keydata])).encode()
            #self.iv=self.L.Token_secrets_token[self.keydata]
            #padding = 16-len(self.data)%16
            #padding = cbytes(chr(padding)*padding)
            #self.cipher = AES.new(self.keydata, AES.MODE_CBC, self.iv)
            #self.output= self.cipher.encrypt(cbytes(self.data+padding))
            #self.ClientDB[self.keydata]=self.output
            #return self.output
        #else:
            #raise  Exception("Could not find information about that token in the database data!")

    #def Decryption_Token(self,Token:bytes,IV_RSA:bytes,Keyfile:str='private_key.pem'):
        #self.Token=Token
        #self.iv_RSA=IV_RSA
        #self.file=Keyfile
        #if (self.Token==list and type(Token).__name__=="bytes" and [self.keys for self.keys in self.Server_DB.keys() if self.keys in self.Token]):
        #try:
            #self.h = open(self.file, 'rb')  
            #self.private_key = RSA.import_key(self.h.read())
            #self.cipher_rsa = PKCS1_OAEP.new(self.private_key)
            #self.h.close() 
            #self.Token_decrypt = self.cipher_rsa.decrypt(self.Token)
            #return self.Token_decrypt
        #except FileNotFoundError:
            #raise Exception("The path to the specified key file could not be found!")
        #else:
            #raise  Exception("Could not find information about that token in the database data!")

    #def Decryption_userdata(self,Token:bytes):
        #self.keydata = Token
        #if self.keydata in self.Server_DB.keys():
            #self.data=(str(self.Server_DB[self.keydata])).encode()
            #self.iv=self.L.Token_secrets_token[self.keydata]
            #self.cipher = AES.new(self.keydata, AES.MODE_CBC, self.iv)
            #self.output= self.cipher.dencrypt(self.data)
            #self.Server_DB[self.keydata]=self.output
            #return self.output
        #else:
            #raise  Exception("Could not find information about that token in the database data!")
