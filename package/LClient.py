from LonginusPyPiAlpha import Longinus
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import subprocess,threading,sys,os
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
from hashlib import blake2b
from argon2 import PasswordHasher
import msvcrt,re,base64,hmac,pickle
import json
import struct

__all__=['Client']

class Client:
    L=Longinus()
    ClientDB:dict=dict()
    def __init__(self,set_addr:str='127.0.0.1',set_port:int=9997):
        self.addr=set_addr;self.port=set_port;self.recv_datas=bytes();self.SignUp_data=list;self.Cypherdata:bytes
        self.userid=str();self.pwrd=bytes();self.udata=bytes();self.head=bytes();self.rsa_keys:bytes=bytes()
        self.cipherdata=bytes();self.s=socket();self.token:bytes;self.atoken:bytes=bytes;self.rtoken:bytes
        self.Cypher_userid=bytes();self.Cypher_userpw=bytes();self.header=bytes();self.session_id=bytes()
        self.cookie=dict();self.temp_userid=bytes();self.temp_userpw=bytes()

    def client_start(self):
        self.addr=input('Enter the server address to connect to : ');self.port=int(input('Enter the server port to connect to : '))
        try:
            if self.cookie_checker()==True:
                print('login')
                self.cookie_loader()
                self.login_function()
                while True:
                    self.receive_function()
                    self.protocol_execution()
            else:
                self.client_hello()
                while True:
                    self.receive_function()
                    self.protocol_execution()
        except ConnectionRefusedError:
            print('server not found')

    def request(self,set_version='0.2.8'):
        self.req=input('send : ')
        self.Cypher_data=base64.b85encode(self.encryption_aes(self.req.encode())).decode()
        self.Create_json_object(content_type='client_master_secret',platform='client',version=set_version,
                                        addres=gethostbyname(gethostname()),protocol='request',session_id=self.session_id,
                                        session_id_length=len(self.session_id),master_secret=self.Cypher_data)
        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
        self.send(self.verified_jsobj_dump)

    def receive_function(self):
        self.recv_head()
        self.recv()
        self.json_decompress()
        self.error_detector()

    def login_function(self,set_version='0.2.8'):
        self.injecter()
        self.SignUp()
        self.temp_userid=self.decryption_aes(base64.b85decode(self.Cypher_userid))
        self.temp_userpw=self.decryption_aes(base64.b85decode(self.Cypher_userpw))
        if (self.SignUp_data=={'userid':self.temp_userid.decode(), 'userpw': self.temp_userpw.decode()}):
            self.Create_json_object(content_type='client_master_secret',platform='client',version=set_version,
                                                addres=gethostbyname(gethostname()),protocol='login',session_id=self.session_id,
                                                session_id_length=len(self.session_id))
            self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
            print(self.verified_jsobj_dump)
            self.send(self.verified_jsobj_dump)
        else:
            print('Your username or password is different!')

    def Sign_Up_function(self,set_version='0.2.8'):
        self.injecter()
        self.SignUp()
        self.session_id=self.atoken
        self.Cypher_userid=base64.b85encode(self.encryption_aes(self.verified_userid.encode())).decode()
        self.Cypher_userpw=base64.b85encode(self.encryption_aes(self.verified_userpw.encode())).decode()
        self.Create_json_object(content_type='client_master_secret',platform='client',version=set_version,
                                            addres=gethostbyname(gethostname()),protocol='Sign_Up',session_id=self.session_id,
                                            session_id_length=len(self.session_id),userid=self.Cypher_userid,userpw=self.Cypher_userpw)
        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
        self.send(self.verified_jsobj_dump)

    def cookie_checker(self):
        self.dir=os.listdir(os.path.dirname(os.path.realpath(__file__)))
        if ('cookie' in self.dir):
            return True

    def cookie_generator(self):
        self.cookie={'user_id':self.Cypher_userid,'user_pw':self.Cypher_userpw,'master_key':self.master_key,'session_id':self.session_id}
        with open('cookie','wb') as f:
            pickle.dump(str(self.cookie).encode(),f)
        print(self.cookie)

    def cookie_loader(self):
        with open('cookie','rb') as f:
            self.cookie=pickle.load(f)
        self.cookie=eval(self.cookie.decode())
        self.Cypher_userid=self.cookie['user_id']
        self.Cypher_userpw=self.cookie['user_pw']
        self.master_key=self.cookie['master_key']
        self.session_id=self.cookie['session_id']
        print(self.cookie)


    def client_hello(self,set_version='0.2.8'):
         self.rtoken=self.L.Random_Token_generator()
         self.Create_json_object(content_type='handshake',platform='client',version=set_version,
                                            addres=gethostbyname(gethostname()),protocol='client_hello',
                                            random_token=self.rtoken.decode(),random_token_length=len(self.rtoken),
                                            )
         self.send(self.jsobj_dump.encode())

    def client_key_exchange(self,set_version='0.2.8'):
        self.pre_master_key_generator()
        self.Cypherdata=base64.b85encode(self.encryption_rsa(self.rsa_keys,self.pre_master_key))
        self.rtoken=self.L.Random_Token_generator()
        self.Create_json_object(content_type='handshake',platform='client',version=set_version,
                                            addres=gethostbyname(gethostname()),protocol='client_key_exchange',
                                            pre_master_key=self.Cypherdata.decode())
        self.send(self.jsobj_dump.encode())
        self.master_key=self.pre_master_key
        self.pre_master_key=None

    def Create_json_object(self,content_type:str=None,platform:str=None,version:str=None,
                                        addres:str=None,protocol:str=None,random_token:str=None,
                                        random_token_length:str=None,userid:str=None,userpw:str=None,
                                        pre_master_key:str=None,session_id:str=None,session_id_length:str=None,
                                        master_secret:str=None):
        self.jsobj={
            'content-type':content_type, 
            'platform':platform,
            'version':version,
            'addres':addres,
            'body':{'protocol':protocol,
                        'random_token':random_token,
                        'random_token_length':random_token_length,
                        'session_id':session_id,
                        'session_id_length':session_id_length,
                        'userid':userid,
                        'userpw':userpw,
                        'pre_master_key':pre_master_key,
                        'master_secret':master_secret
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        return self.jsobj_dump


    def merge_data(self,data:bytes):
        self.body=base64.b85encode(data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        return self.send_data
    
    def send(self,data:str):
        self.s=socket()
        self.s.connect((self.addr,self.port))
        self.s.send(self.merge_data(data))


    def json_decompress(self):
        self.recv_datas=base64.b85decode(self.recv_datas).decode()
        try:
            self.jsobj = json.loads(self.recv_datas)
            self.server_version=self.jsobj["version"]
            self.token=self.jsobj['body']['random_token']
            self.atoken=self.jsobj['body']['session-id']
            self.platform=self.jsobj["platform"]
            self.protocol=self.jsobj['body']["protocol"]
            self.content_type=self.jsobj["content-type"]
            self.rsa_keys=self.jsobj['body']["public-key"]
            self.server_error=self.jsobj['body']["server_error"]
            self.master_secret=self.jsobj['body']['master_secret']
        except json.decoder.JSONDecodeError as e:
            self.jsobj = self.recv_datas[:len(self.recv_datas)-80]
            self.hmac_hash=base64.b85decode((self.recv_datas[len(self.recv_datas)-80:].encode()))
            if self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b):
                self.jsobj = json.loads(self.jsobj)
                self.server_version=self.jsobj["version"]
                self.token=self.jsobj['body']['random_token']
                self.atoken=self.jsobj['body']['session-id']
                self.platform=self.jsobj["platform"]
                self.protocol=self.jsobj['body']["protocol"]
                self.content_type=self.jsobj["content-type"]
                self.rsa_keys=self.jsobj['body']["public-key"]
                self.server_error=self.jsobj['body']["server_error"]
                self.master_secret=self.jsobj['body']['master_secret']


    def protocol_execution(self):
        if (self.content_type=='handshake' and self.protocol=='server_hello'):
            self.client_key_exchange()
        elif (self.content_type=='server_master_secret' and self.protocol=='session_ids'):
            self.Sign_Up_function()
        elif (self.content_type=='Sign_Up-report' and self.protocol=='welcome! '):
            self.cookie_generator()
            print('\nsign-up successful')
            self.request()
        elif (self.content_type=='login-report' and self.protocol=='welcome! '):
            print('\nlogin successful')
            self.request()
        elif (self.content_type=='server_master_secret' and self.protocol=='response'):
            self.master_secret=self.decryption_aes(base64.b85decode(self.master_secret))
            print('server : ',self.master_secret)
            self.request()
        elif (self.content_type=='return_error' and self.protocol=='error'):
            print('server : ',self.server_error)
            self.error_detector()

    def error_detector(self):
        if self.server_error!=None:
            if self.server_error==' [ unexpected error ]: The user could not be found. Please proceed to sign up':
                self.client_hello()
            else:
                print(self.server_error)
                self.client_start()


    def pre_master_key_generator(self):
        self.pre_master_key=self.L.master_key_generator(self.token.encode(),self.rtoken)
        return self.pre_master_key

    def send_client(self,data):
        self.s.sendall(self.merge_data(data))

    def recv_head(self):
        #try:
        self.header=self.s.recv(4)
        self.header=int(str(struct.unpack("I",self.header)).split(',')[0].split('(')[1])
        return self.header
        #except:
            #print('An unexpected error occurred')

    def recv(self):
        self.recv_datas=bytes()
        if self.header<2048:
            self.recv_datas=self.s.recv(self.header)
            self.cipherdata=self.recv_datas
        elif self.header>=2048:
            self.recv_datas=bytearray()
            for i in range(int(self.header/2048)):
                self.recv_datas.append(self.s.recv(2048))
                print("  [ Downloading "+str(self.addr)+" : "+str(2048*i/self.header*100)+" % ]"+" [] Done... ] ")
            print("  [ Downloading "+str(self.addr)+"100 % ] [ Done... ] ",'\n')
            self.recv_datas=bytes(self.recv_datas)
        return self.recv_datas

    def SignUp(self):
        self.temp_data=bytearray()
        self.Userpwrd=self.pwrd.decode()
        if (" " not in self.userid and "\r\n" not in self.userid and "\n" not in self.userid and "\t" not in self.userid and re.search('[`~!@#$%^&*(),<.>/?]+', self.userid) is None):
            if len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd:
                self.SignUp_data={'userid':self.userid,'userpw':self.Userpwrd}
                self.verified_userpw=self.SignUp_data['userpw'];self.verified_userid=self.SignUp_data['userid']
                return self.SignUp_data
            else:
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

    def ReSign(self,Token:bytes):
        pass

    def Logout():
        pass

    def Rename():
        pass

    def Repwrd():
        pass

    def emall_verify():
        pass

    def encryption_aes(self,data:bytes):
         self.data=base64.b85encode(data)
         self.send_data=bytes
         session_key = self.master_key
         cipher_aes = AES.new(session_key, AES.MODE_EAX)
         ciphertext, tag = cipher_aes.encrypt_and_digest(self.data)
         self.send_data= cipher_aes.nonce+ tag+ ciphertext
         return self.send_data

    def decryption_aes(self,set_data):
        nonce=set_data[:16]
        tag=set_data[16:32]
        ciphertext =set_data[32:-1]+set_data[len(set_data)-1:]
        session_key = self.master_key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self.decrypt_data=base64.b85decode(data)
        return self.decrypt_data

    def hmac_cipher(self,data):
        self.hmac_data=hmac.digest(self.master_key,data,blake2b)
        self.verified_data=data+base64.b85encode(self.hmac_data)
        return self.verified_data

    def encryption_rsa(self,set_pul_key:str,data:bytes):
        public_key = RSA.import_key(set_pul_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.encrypt_data = cipher_rsa.encrypt(base64.b85encode(data))
        return self.encrypt_data

    def decryptio_rsa(self,set_prv_key:str,encrypt_data:bytes):
        private_key = RSA.import_key(set_prv_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        self.decrypt_data=base64.b85decode(cipher_rsa.decrypt(encrypt_data))
        return self.decrypt_data

    def Decryption_Token(self):
        private_key = RSA.import_key(open(self.set_keys['private_key']).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = base64.b64decode(cipher_rsa.decrypt(self.Token))
        return session_key

    def injecter(self):
        self.pwrd=bytes()
        self.userid=input("Please enter your name : ")
        self.input_num=0
        print("Please enter your password : ",end="",flush=True)
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
