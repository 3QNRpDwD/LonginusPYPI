from LonginusPyPiAlpha import Longinus
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from diffiehellman import DiffieHellman
import subprocess,threading,sys,os
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
from hashlib import sha256
from argon2 import PasswordHasher
import msvcrt,re,base64,hmac,pickle
import json
import struct

__all__=['Client']

class Client:
    L=Longinus()
    ClientDB:dict=dict()
    def __init__(self,set_addr:str='127.0.0.1',set_port:int=9997,set_version='0.4.6'):
        self.addr=set_addr;self.port=set_port;self.recv_datas=bytes();self.string_check_data=list;self.Cypherdata:bytes
        self.userid=str();self.pwrd=bytes();self.udata=bytes();self.head=bytes();self.rsa_keys:bytes=bytes()
        self.cipherdata=bytes();self.s=socket();self.token:bytes;self.atoken:bytes=bytes;self.rtoken:bytes
        self.Cypher_userid=bytes();self.Cypher_userpw=bytes();self.header=bytes();self.session_id=bytes()
        self.cookie=dict();self.temp_userid=bytes();self.temp_userpw=bytes();self.login_id='';self.set_version=set_version
        self.cookie_login_id='';self.cookie_master_key=''

#===================================================================================================================================#
#===================================================================================================================================#

    def client_start(self):
            self.addr=input('Enter the server address to connect to : ');self.port=int(input('Enter the server port to connect to : '))
            self.client_hello()
            while True:
                self.receive_function()
                self.protocol_execution()

#===================================================================================================================================#
#===================================================================================================================================#

    def client_hello(self):
        # try:
            self.rtoken=self.L.Random_Token_generator()
            self.Create_json_object(content_type='handshake',platform='client',version=self.set_version,
                                                addres=gethostbyname(gethostname()),protocol='client_hello',
                                                random_token=self.rtoken.decode(),random_token_length=len(self.rtoken),
                                                )
            self.s=socket()
            self.s.connect((self.addr,self.port))
            self.send(base64.b85encode(self.jsobj_dump.encode()))
        # except ConnectionRefusedError as e:
        #     print(e)

#===================================================================================================================================#
#===================================================================================================================================#

    def receive_function(self):
        self.recv_head()
        self.recv()
        self.json_decompress()
        self.error_detector()

#===================================================================================================================================#
#===================================================================================================================================#

    def protocol_execution(self):
        if (self.content_type=='handshake' and self.protocol=='server_hello'):
            self.client_key_exchange()
        elif (self.content_type=='handshake' and self.protocol=='Change_Cipher_Spec'):
            if self.cookie_checker()==True:
                print('You are already logged in')
                self.cookie_loader()
                self.request()
            else:
                self.session_id=self.atoken
                cmd=input('\nPlease login or sign up (l/s) :')
                if cmd=='l':
                    self.Join('login')
                elif cmd=='s':
                    self.Join('Sign_Up')
                else:
                    sys.exit()
        elif (self.content_type=='Sign_Up-report' and self.protocol=='Sign_up_complete'):
            print('\nSign up is complete')
            print('Please login\n')
            self.Join('login')
        elif (self.content_type=='login-report' and self.protocol=='welcome! '):
            print('\nlog-in succeed!')
            self.cookie_generator()
            self.request()
        elif (self.content_type=='server_master_secret' and self.protocol=='response'):
            self.master_secret=self.decryption_aes(base64.b85decode(self.master_secret),self.cookie_master_key)
            print('Server :',self.master_secret.decode())
            self.request()
        elif (self.content_type=='return_error' and self.protocol=='error'):
            self.error_detector()

#===================================================================================================================================#
#===================================================================================================================================#

    def client_key_exchange(self):
        self.pre_master_key_generator()
        self.pul_key=self.rsa_keys
        self.Cypherdata=base64.b85encode(self.encryption_rsa(self.pul_key,self.pre_master_key)).decode()
        self.rtoken=self.L.Random_Token_generator()
        self.Create_json_object(content_type='handshake',platform='client',version=self.set_version,
                                            addres=gethostbyname(gethostname()),protocol='client_key_exchange',
                                            pre_master_key=self.Cypherdata)
        self.send(base64.b85encode(self.jsobj_dump.encode()))
        self.master_key=self.pre_master_key
        self.pre_master_key=None

#===================================================================================================================================#
#===================================================================================================================================#

    def Cypher_user_data(self):
        self.injecter()
        self.string_check()
        self.Cypher_userid=base64.b85encode(self.encryption_aes(self.verified_userid.encode(),self.master_key)).decode()
        self.Cypher_userpw=base64.b85encode(self.encryption_aes(self.verified_userpw.encode(),self.master_key)).decode()

    def Join(self,set_protocol):
        self.Cypher_user_data()
        self.Create_json_object(content_type='client_master_secret',platform='client',version=self.set_version,
                                addres=gethostbyname(gethostname()),protocol=set_protocol,
                                session_id=self.session_id,session_id_length=len(self.session_id),
                                userid=self.Cypher_userid,userpw=self.Cypher_userpw)

        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode(),self.master_key)
        self.s=socket()
        self.s.connect((self.addr,self.port))
        self.send(self.verified_jsobj_dump)

#===================================================================================================================================#
#===================================================================================================================================#

    def cookie_generator(self):
        self.cookie={'login_id':self.login_id,'master_key':self.master_key}
        print(self.cookie)
        with open('cookie','wb') as f:
            pickle.dump(self.cookie,f)

#===================================================================================================================================#
#===================================================================================================================================#

    def request(self):
        self.req=input('send : ')
        self.Cypher_data=base64.b85encode(self.encryption_aes(self.req.encode(),self.cookie_master_key)).decode()
        self.Create_json_object(content_type='client_master_secret',platform='client',version=self.set_version,
                                        addres=gethostbyname(gethostname()),protocol='request',login_id=self.cookie_login_id,
                                        master_secret=self.Cypher_data)
        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode(),self.cookie_master_key)
        self.s=socket()
        self.s.connect((self.addr,self.port))
        self.send(self.verified_jsobj_dump)

#===================================================================================================================================#
#===================================================================================================================================#

    def cookie_loader(self):
        with open('cookie','rb') as f:
            self.cookie=pickle.load(f)
        self.cookie_login_id=self.cookie['login_id']
        self.cookie_master_key=self.cookie['master_key']
        print(self.cookie)

#===================================================================================================================================#
#===================================================================================================================================#

    def Create_json_object(self,content_type:str=None,platform:str=None,version:str=None,
                                        addres:str=None,protocol:str=None,random_token:str=None,
                                        random_token_length:str=None,userid:str=None,userpw:str=None,
                                        pre_master_key:str=None,session_id:str=None,session_id_length:str=None,
                                        master_secret:str=None,login_id=None,login_id_length=None):
        self.jsobj={
            'content-type':content_type, 
            'platform':platform,
            'version':version,
            'addres':addres,
            'body':{'protocol':protocol,
                    'random_token':random_token,
                    'random_token_length':random_token_length,
                    'session-id':session_id,
                    'session-id_length':session_id_length,
                    'login-id':login_id,
                    'login-id_length':login_id_length,
                    'userid':userid,
                    'userpw':userpw,
                    'pre_master_key':pre_master_key,
                    'master_secret':master_secret
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        return self.jsobj_dump

    def json_decompress(self):
        if b'.' not in self.recv_datas:
            self.jsobj = base64.b85decode(self.recv_datas).decode()
            self.jsobj = json.loads(self.jsobj)
        else:
            self.recv_obj=self.recv_datas.decode().split('.')
            self.jsobj = base64.b85decode(self.recv_obj[0].encode()).decode()
            self.hmac_hash = base64.b85decode(self.recv_obj[1].encode())
            if self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),sha256):
                self.jsobj = json.loads(self.jsobj.decode())
            elif self.hmac_hash==hmac.digest(self.cookie_master_key,self.jsobj.encode(),sha256):
                self.jsobj = json.loads(self.jsobj)
        self._assign_variables()

    def _assign_variables(self):
        self.server_version=self.jsobj["version"]
        self.token=self.jsobj['body']['random_token']
        self.atoken=self.jsobj['body']['session-id']
        self.login_id = self.jsobj['body']['login-id']
        self.platform=self.jsobj["platform"]
        self.protocol=self.jsobj['body']["protocol"]
        self.content_type=self.jsobj["content-type"]
        self.rsa_keys=self.jsobj['body']["public-key"]
        self.server_error=self.jsobj['body']["server_error"]
        self.master_secret=self.jsobj['body']['master_secret']
        return {
                'content-type':self.content_type, 
                'platform':self.platform,
                'body':{'protocol':self.protocol,
                            'random_token':self.token,
                            'session-id':self.atoken,
                            'login-id':self.login_id,
                            'public-key':self.rsa_keys,
                            'master_secret':self.master_secret,
                            'server_error':self.server_error
                            }
            }
#===================================================================================================================================#
#===================================================================================================================================#

    def recv_head(self):
        try:
            self.header=self.s.recv(4)
            self.header=int(str(struct.unpack("I",self.header)).split(',')[0].split('(')[1])
            return self.header
        except Exception as e:
            print(e)

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

#===================================================================================================================================#
#===================================================================================================================================#

    def send(self, data: bytes):
        head = struct.pack("I", len(data))
        self.s.sendall(head + data)
        return head + data

#===================================================================================================================================#
#===================================================================================================================================#

    def pre_master_key_generator(self):
        self.pre_master_key=self.L.master_key_generator(self.token.encode(),self.rtoken)
        return self.pre_master_key

    def send_client(self,data):
        self.s.sendall(self.merge_data(data))

    def string_check(self):
        self.temp_data=bytearray()
        self.Userpwrd=self.pwrd.decode()
        if (" " not in self.userid and "\r\n" not in self.userid and "\n" not in self.userid and "\t" not in self.userid and re.search('[`~!@#$%^&*(),<.>/?]+', self.userid) is None):
            if len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd:
                self.string_check_data={'userid':self.userid,'userpw':self.Userpwrd}
                self.verified_userpw=self.string_check_data['userpw'];self.verified_userid=self.string_check_data['userid']
                return self.string_check_data
            else:
                raise  Exception("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            raise  Exception("Name cannot contain spaces or special characters")

#===================================================================================================================================#
#===================================================================================================================================#

    def error_detector(self):
        if self.server_error!=None:
            if self.server_error==' [ unexpected error ]: The user could not be found. Please proceed to sign up':
                self.Sign_Up_function()
            elif self.server_error==' [ unexpected error ]: A user with the same name already exists':
                print('\n')
                print(self.server_error)
                self.Sign_Up_function()
            else:
                print('\n')
                print(self.server_error)
                self.client_start()

#===================================================================================================================================#
#===================================================================================================================================#

    def hmac_cipher(self, data: bytes,master_key):
        hmac_data = base64.b85encode(hmac.digest(master_key, data, sha256))
        verified_data = base64.b85encode(data) +b'.'+hmac_data
        return verified_data

    def encryption_rsa(self,set_pul_key:str,data:bytes):
        public_key = RSA.import_key(set_pul_key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.encrypt_data = cipher_rsa.encrypt(base64.b85encode(data))
        return self.encrypt_data

    def encryption_aes(self,data:bytes,master_key):
         self.data=base64.b85encode(data)
         self.encrypt_data=bytes()
         cipher_aes = AES.new(master_key, AES.MODE_EAX)
         ciphertext, tag = cipher_aes.encrypt_and_digest(self.data)
         self.encrypt_data= cipher_aes.nonce+ tag+ ciphertext
         return self.encrypt_data

#===================================================================================================================================#
#===================================================================================================================================#

    def decryption_aes(self,set_data,master_key):
        nonce=set_data[:16]
        tag=set_data[16:32]
        ciphertext =set_data[32:-1]+set_data[len(set_data)-1:]
        session_key = master_key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self.decrypt_data=base64.b85decode(data)
        return self.decrypt_data

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

#===================================================================================================================================#
#===================================================================================================================================#

    def cookie_checker(self):
        self.dir=os.listdir(os.getcwd())
        if ('cookie' in self.dir):
            return True

#===================================================================================================================================#
#===================================================================================================================================#

    def injecter(self):
        self.pwrd=bytes()
        self.userid=input("\nPlease enter your name : ")
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

#===================================================================================================================================#
#===================================================================================================================================#

Client().client_start()