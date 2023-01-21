from LonginusPyPiAlpha import Longinus
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import subprocess,threading,sys,os,json
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
from hashlib import blake2b
from argon2 import PasswordHasher
import re,base64,requests,struct,hmac,logging,pickle
from multiprocessing import Process

__all__=['Server']


Login_list:list=list();path:str=r'C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\package\LonginusPYPL';set_port:int=9997;set_addr:str='0.0.0.0';
s=socket();
ip:str=str();Token:bytes=bytes();Token_data:dict=dict();Token_DB:dict=dict()
rdata:str='';platform:str='shell';head='';c='';addr='';Token_RSA:bytes=bytes();RSA_Key:dict=Longinus().Create_RSA_key()
address=list();sessions:dict=dict();prv_key:str=open(RSA_Key['private_key']).read();pul_key:str=open(RSA_Key['public_key']).read();userdata:bytes=bytes()
Server_DB:dict=dict();new_session:dict=dict()

class Server:

    L= Longinus()
    def __init__(self):
        self.set_port=set_port;self.set_addr=set_addr;self.path=path;self.cipherdata=bytes();self.decrypt_data=bytes()
        self.s=s;self.ip=ip;self.Token=Token;self.Login_list='Login_list';self.body=bytes();self.temp_db=None;self.prv_key=prv_key
        self.Token_data=Token_data;self.Token_DB=Token_DB;self.rdata=rdata;self.platform=platform;self.pul_key=pul_key
        self.head=head;self.c=c;self.addr=addr;self.Token_RSA=Token_RSA;self.address=address;self.sessions=sessions
        self.pul_key=pul_key;self.userdata=userdata;self.Server_DB=Server_DB;self.new_session=new_session;self.temp=''
        self.jsobj:str;self.client_version:str;self.rtoken:bytes;self.session_id:str;self.platform:str;self.internal_ip:str;self.session_keys:dict=dict()
        self.protocol:str='Preliminaries';self.content_type:str;self.hmac_hash=bytes();self.Cypher_userid=bytes();self.Cypher_userpw=bytes()
        self.userid=str();self.userpw=str();self.session_data=dict();self.pre_master_key=bytes();self.reqdata=bytes();self.master_key=bytes()
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.stream_handler)
        self.file_handler = logging.FileHandler('server.log')
        self.file_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.file_handler)

    def start_server(self):
        self.session_checker()
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '
        self.s.bind((self.set_addr,self.set_port))
        self.s.listen(0)
        self.logger.info('[ Server started at : '+self.req+' ] ')
        while True:
            #try:
                self.session_id:str=''
                self.receive_function()
                self.protocol_execution()
                self.saveing()
            #except Exception as e:
                #self.error_handler(str(e).encode())

    def receive_function(self):
        print('유저 기다리는중')
        self.c,self.addr=self.s.accept();
        print('유저 연결됨')
        self.recv_head()
        self.recv_server()
        self.json_decompress()

    def response_function(self):
        #if self.Token_DB[self.session_id.encode()]['User addres']==self.ip:
        self.reqdata=self.decryption_aes(base64.b85decode(self.master_secret))
        self.logger.info(str(self.addr)+' [ get request ]: '+self.reqdata.decode())
        self.Create_json_object(content_type='server_master_secret',platform='server',version='0.2.6',
                                    protocol='response',master_secret=base64.b85encode(self.encryption_aes(self.reqdata)).decode())
        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
        self.send(self.verified_jsobj_dump)
        #else:
            #self.error_handler('An attempt to sign up from another region was detected during member registration.')

    def protocol_execution(self):
        print(self.content_type,self.protocol)
        if (self.content_type=='handshake' and self.protocol=='client_hello'):
            self.server_hello()
        elif (self.content_type=='handshake' and self.protocol=='client_key_exchange'):
            self.Create_master_secret()
        elif (self.content_type=='client_master_secret' and self.protocol=='Sign_Up'):
            self.Sign_Up_function()
        elif (self.content_type=='client_master_secret' and self.protocol=='request'):
            self.response_function()
        elif (self.content_type=='client_master_secret' and self.protocol=='login'):
            self.login_function()
        else:
            self.error_handler('Abnormal access detected')

    def Sign_Up_function(self):
        if self.Token_DB[self.session_id.encode()]['User addres']==self.ip:
            self.Decrypt_user_data()
            self.SignUp()
            self.session_classifier()
            self.Create_json_object(content_type='Sign_Up-report',platform='server',version='0.2.6',
                                        protocol='welcome! ',)
            self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
            self.send(self.verified_jsobj_dump)
        else:
            self.error_handler('An attempt to sign up from another region was detected during member registration.')

    def login_function(self):
        if (self.session_id.encode() in self.sessions.keys() and self.sessions[self.session_id.encode()]['User addres']==self.ip):
            self.Create_json_object(content_type='login-report',platform='server',version='0.2.6',
                                        protocol='welcome! ',)
            self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
            self.send(self.verified_jsobj_dump)
        else:
            self.error_handler('The user could not be found. Please proceed to sign up')

    def session_checker(self):
        self.dir=os.listdir(os.getcwd())
        if ('Sessions' in self.dir and 'Session_data' in self.dir and 'Session_keys' in self.dir and 'port' in self.dir and 'addr' in self.dir and 'Login_list' in self.dir):
            self.loading()
            return True

    def server_hello(self,set_version='0.2.8'):
         self.token=self.L.Random_Token_generator()
         self.Create_json_object(content_type='handshake',platform='server',version=set_version,
                                              protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                              public_key=self.pul_key,public_key_length=len(self.pul_key))
         self.send(self.jsobj_dump.encode())
         self.logger.info(str(self.addr)+' [ server hello transmission complete ] ')
         self.c.close()
         return self.jsobj_dump

    def Create_master_secret(self,set_version='0.2.8'):
        self.master_key=self.decryption_rsa(self.prv_key,base64.b85decode(self.pre_master_key))
        self.Token,self.Token_data=self.L.session_id_generator(16,self.ip,self.internal_ip)
        self.logger.info(str(self.addr)+' [ Token Issued ]: '+str(self.Token))
        self.Token_DB.setdefault(self.Token,self.Token_data)
        self.session_keys.setdefault(self.Token,self.master_key)
        self.logger.info(str(self.addr)+' [ Session creation complete ] ')
        self.logger.info(str(self.addr)+' [ Master secret creation complete ] ')
        self.Create_json_object(content_type='server_master_secret',platform='server',version=set_version,
                                              protocol='session_ids',session_id=self.Token.decode(),session_id_length=len(self.Token))
        self.send(self.jsobj_dump.encode())
        self.logger.info(str(self.addr)+' [ Access token send ] ')

    def send(self,data:str):
        self.c.send(self.merge_data(data))
        self.logger.info(str(self.addr)+' [ response complete ] ')
        self.c.close()

    def merge_data(self,data:bytes):
        self.body=base64.b85encode(data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        self.logger.info(str(self.addr)+' [ Transmission data size ]: '+str(len(self.body)))
        return self.send_data

    def recv_head(self):
        #try:
        self.logger.info('[ Connected with ]: '+str(self.addr))
        self.head=self.c.recv(4)
        self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        self.logger.info(str(self.addr)+' [ Header received ]: '+str(self.head))
        self.ip=str(self.addr).split("'")[1]
        return self.head,self.c,self.addr
        #except:
            #print('An unexpected error occurred')

    def recv_server(self):
        print('\nrecv')
        self.recv_datas=bytes()
        if self.head<2048:
            self.recv_datas=self.c.recv(self.head)
            self.cipherdata=self.recv_datas
        elif self.head>=2048:
            self.recv_datas=bytearray()
            for i in range(int(self.head/2048)):
                self.recv_datas.append(self.c.recv(2048))
                self.logger.info(str(self.addr)+"  [ receiving data "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ]"+" [] Done... ] "+self.session_id)
            self.logger.info(str(self.addr)+"  [ receiving data "+str(self.addr)+"100 % ] [ Done... ] "+self.session_id)
            self.recv_datas=bytes(self.recv_datas)
        self.logger.info(str(self.addr)+' [ data received ]: '+self.session_id)
        self.logger.info(str(self.addr)+' [ Get requested ]: '+self.session_id)
        return self.recv_datas
        #except:
            #print('An unexpected error occurred')


    def json_decompress(self):
        self.recv_datas=base64.b85decode(self.recv_datas).decode()
        self.logger.info(str(self.addr)+str(self.recv_datas))
        try:
            self.jsobj = json.loads(self.recv_datas)
            self.client_version=self.jsobj["version"]
            self.rtoken=self.jsobj['body']['random_token']
            self.session_id=self.jsobj['body']['session_id']
            self.platform=self.jsobj["platform"]
            self.internal_ip=self.jsobj["addres"]
            self.protocol=self.jsobj['body']["protocol"]
            self.content_type=self.jsobj["content-type"]
            self.Cypher_userid=self.jsobj['body']["userid"]
            self.Cypher_userpw=self.jsobj['body']['userpw']
            self.pre_master_key=self.jsobj['body']['pre_master_key']
            self.master_secret=self.jsobj['body']['master_secret']
            self.logger.info(str(self.addr)+' [ variable assignment done ] ')
        except json.decoder.JSONDecodeError as e:
            self.jsobj = self.recv_datas[:len(self.recv_datas)-80]
            self.hmac_hash=base64.b85decode((self.recv_datas[len(self.recv_datas)-80:].encode()))
            self.jsobj = json.loads(self.recv_datas[:len(self.recv_datas)-80])
            self.client_version=self.jsobj["version"]
            self.rtoken=self.jsobj['body']['random_token']
            self.session_id=self.jsobj['body']['session_id']
            self.platform=self.jsobj["platform"]
            self.internal_ip=self.jsobj["addres"]
            self.protocol=self.jsobj['body']["protocol"]
            self.content_type=self.jsobj["content-type"]
            self.Cypher_userid=self.jsobj['body']["userid"]
            self.Cypher_userpw=self.jsobj['body']['userpw']
            self.pre_master_key=self.jsobj['body']['pre_master_key']
            self.master_secret=self.jsobj['body']['master_secret']
            self.logger.info(str(self.addr)+' [ hmac hash scanned ]')
            self.logger.info(str(self.addr)+' [ variable assignment done ] ')
        return

    def error_handler(self,msg="None"):
        self.logger.info(str(self.addr)+' [ unexpected error ]: '+msg)
        self.Create_json_object(content_type='return_error',platform='server',version='0.2.6',
                                            protocol='error',
                                            server_error=' [ unexpected error ]: '+msg)
        self.send(self.jsobj_dump.encode())
        self.c.close()

    def Create_json_object(self,content_type=None,platform=None,version=None,
                                        protocol=None,random_token=None,random_token_length=None,
                                        public_key=None,public_key_length=None,server_error=None,
                                        session_id=None,session_id_length=None,master_secret=None):
        self.jsobj={
            'content-type':content_type, 
            'platform':platform,
            'version':version,
            'body':{'protocol':protocol,
                        'random_token':random_token,
                        'random_token_length':random_token_length,
                        'session-id':session_id,
                        'session-id_length':session_id_length,
                        'public-key':public_key,
                        'public-key_length':public_key_length,
                        'master_secret':master_secret,
                        'server_error':server_error
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        self.logger.info(str(self.addr)+str(self.jsobj_dump))
        return self.jsobj_dump

    def Decrypt_user_data(self):
        self.session_data.setdefault(self.session_id,[self.Cypher_userid,self.Cypher_userpw])
        self.userid=self.decryption_aes(base64.b85decode(self.session_data[self.session_id][0]))
        self.userpw=self.decryption_aes(base64.b85decode(self.session_data[self.session_id][1]))
        self.session_data.update({self.session_id:[self.userid.decode(),self.userpw.decode()]})
        print(self.session_data)
        return self.userid,self.userpw

    def Session_credentials(self):
        print(self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b))
        if self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b):
            self.session_data.setdefault(self.session_id,[self.Cypher_userid,self.Cypher_userpw])
            self.logger.info(str(self.addr)+' [ Session Credentials Completed ]: '+self.session_id)
        else:
            self.error_handler('Message tampering confirmed')

    def session_classifier(self):
        self.verified_UserID=self.session_data[self.session_id][0]
        self.verified_Userpw=self.session_data[self.session_id][1]
        if (self.verified_UserID=='Guest' or self.verified_UserID=='guest' or self.verified_UserID=='__Guest__' or self.verified_UserID=='__guest__'):
             self.guest_session_creator()
        elif (self.Token_DB[self.session_id.encode()]['User addres']=='127.0.0.1'):
            self.admin_session_creator()
        else:
            self.session_creator()
        return self.verified_UserID

    def admin_session_creator(self):
        self.new_session={self.Token:{'user_id':self.verified_UserID,'user_pw':self.verified_Userpw,'permission_lv':0,'class':'__administrator__'}}
        self.new_session[self.Token].update(Token_DB[self.Token])
        self.sessions.update(self.new_session)
        self.logger.info(str(self.addr)+str(self.new_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.session_id)
        return self.new_session

    def session_creator(self):
        self.new_session={self.Token:{'user_id':self.verified_UserID,'user_pw':self.verified_Userpw,'permission_lv':1,'class':'__user__'}}
        self.new_session[self.Token].update(Token_DB[self.Token])
        self.sessions.update(self.new_session)
        self.logger.info(str(self.addr)+str(self.new_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.session_id)
        return self.new_session

    def guest_session_creator(self):
        self.new_session={self.Token:{'user_id':self.verified_UserID+str(os.urandom(8)),'user_pw':str(os.urandom(16)),'permission_lv':1,'class':'__guest__'}}
        self.new_session[self.Token].update(Token_DB[self.Token])
        self.sessions.update(self.new_session)
        self.logger.info(str(self.addr)+str(self.new_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.session_id)
        return self.new_session

    def SignUp(self):
        self.UserID=self.session_data[self.session_id][0]
        self.Userpwrd=self.session_data[self.session_id][1]
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if (len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd):
                self.basepw=base64.b85encode(self.Userpwrd.encode())
                self.result=bytearray()
                for i in range(len(self.basepw)):
                    self.result.append(self.basepw[i]^self.session_id.encode()[i%len(self.session_id)])
                self.result=bytes(self.result)
                self.verified_Userpw=self.L.pwd_hashing(bytes(self.result))
                self.verified_UserID=self.UserID
                self.session_data.update({self.session_id:[self.verified_UserID,self.verified_Userpw]})
                self.logger.info(str(self.addr)+str({self.session_id:[self.verified_UserID,self.verified_Userpw]}))
                self.logger.info(str(self.addr)+' [ User info update ]: '+self.UserID)
                return {self.session_id:[self.verified_UserID,self.verified_Userpw]}
            else:
                self.error_handler("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            self.error_handler("Name cannot contain spaces or special characters")

    def ReSign(self,Token:bytes):
        pass
#############################################################################################################################################################################################################################
    # def Login(self):
    #     self.unverified_Userid=self.session_data[self.session_id][0]
    #     self.unverified_Userpw=self.session_data[self.session_id][1]
    #     self.verified_UserID=self.sessions[self.session_id]['user_id']
    #     self.verified_Userpw=self.sessions[self.session_id]['user_pw']
    #     if (" " not in self.unverified_Userid and "\r\n" not in self.unverified_Userid and "\n" not in self.unverified_Userid and "\t" not in self.unverified_Userid and re.search('[`~!@#$%^&*(),<.>/?]+', self.unverified_Userid) is None):
    #         if (len(self.unverified_Userpw) > 8 and re.search('[0-9]+', self.unverified_Userpw) is not None and re.search('[a-zA-Z]+', self.unverified_Userpw) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.unverified_Userpw) is not None and " " not in self.unverified_Userpw):
    #             if (PasswordHasher.verify(self.unverified_Userpw,self.user_pw)==True and self.verified_UserID==self.unverified_Userid):
    #                 self.session_data.update({self.session_id:[self.verified_UserID,self.verified_Userpw]})
    #                 self.logger.info(str(self.addr)+' [ user login ]: '+self.UserName)
    #                 return {self.session_id:[self.verified_UserID,self.verified_Userpw]}
    #         else:
    #             self.error_handler("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
    #     else:
    #         self.error_handler("Name cannot contain spaces or special characters")
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
        self.logger.info(str(self.addr)+' [ token deleted ]: '+self.Token)
        del self.Token_DB[self.Token]
        return 'done'

    def hmac_cipher(self,data:bytes):
        print(self.session_keys)
        self.hmac_data=hmac.digest(self.session_keys[self.session_id.encode()],data,blake2b)
        self.verified_data=data+base64.b85encode(self.hmac_data)
        self.logger.info(str(self.addr)+' [ hmac applied ] ')
        return self.verified_data

    def decryption_rsa(self,set_prv_key:bytes,encrypt_data:bytes):
        private_key = RSA.import_key(set_prv_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        self.decrypt_data=base64.b85decode(cipher_rsa.decrypt(encrypt_data))
        self.logger.info(str(self.addr)+' [ key decryption complete ] ')
        return self.decrypt_data

    def encryption_aes(self,data:bytes):
         self.data=base64.b85encode(data)
         self.send_data=bytes
         session_key = self.session_keys[self.session_id.encode()]
         cipher_aes = AES.new(session_key, AES.MODE_EAX)
         ciphertext, tag = cipher_aes.encrypt_and_digest(self.data)
         self.send_data= cipher_aes.nonce+ tag+ ciphertext
         return self.send_data

    def decryption_aes(self,set_data):
        nonce=set_data[:16]
        tag=set_data[16:32]
        ciphertext =set_data[32:-1]+set_data[len(set_data)-1:]
        session_key = self.session_keys[self.session_id.encode()]
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self.decrypt_data=base64.b85decode(data)
        self.logger.info(str(self.addr)+' [ data decryption complete ] ')
        return self.decrypt_data

    def saveing(self):
        self.logger.info(str(self.addr)+'[ Saving database & setting ] ')
        with open('Sessions','wb') as f:
            pickle.dump(self.sessions,f)
        with open('Session_data','wb') as f:
            pickle.dump(self.session_data,f)
        with open('Session_keys','wb') as f:
            pickle.dump(self.session_keys,f)
        with open('Login_list','wb') as f:
            pickle.dump(self.Login_list,f)
        with open('addr','wb') as f:
            pickle.dump(self.set_addr,f)
        with open('port','wb') as f:
            pickle.dump(self.set_port,f)
    
    def loading(self):
        with open('Sessions','rb') as f:
            self.sessions=pickle.load(f)
        with open('Session_data','rb') as f:
            self.session_data=pickle.load(f)
        with open('Session_keys','rb') as f:
            self.session_keys=pickle.load(f)
        with open('Login_list','rb') as f:
            self.Login_list=pickle.load(f)
        with open('addr','rb') as f:
            self.set_addr=pickle.load(f)
        with open('port','rb') as f:
            self.set_port=pickle.load(f)
        self.logger.info(str(self.addr)+'[ load database & setting ]')


