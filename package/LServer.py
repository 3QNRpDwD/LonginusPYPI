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


set_port:int=9997;set_addr:str='0.0.0.0';
s=socket();
ip:str=str();Token:bytes=bytes();Token_data:dict=dict();Token_DB:dict=dict()
rdata:str='';platform:str='shell';head='';c='';addr='';Token_RSA:bytes=bytes();RSA_Key:dict=Longinus().Create_RSA_key()
address=list();sessions:dict=dict();prv_key:str=open(RSA_Key['private_key']).read();pul_key:str=open(RSA_Key['public_key']).read();userdata:bytes=bytes()
Server_DB:dict=dict();new_session:dict=dict()

class Server:

    L= Longinus()
    def __init__(self,version='0.4.6',port=set_port,addres=set_addr):
        self.set_port=port;self.set_addr=addres;self.cipherdata=bytes();self.decrypt_data=bytes()
        self.s=s;self.ip=ip;self.session_id=Token;self.Login_list='Login_list';self.body=bytes();self.temp_db=None;self.prv_key=prv_key
        self.session_id_data=Token_data;self.session_db=Token_DB;self.rdata=rdata;self.platform=platform;self.pul_key=pul_key
        self.head=head;self.c=c;self.addr=addr;self.session_id_RSA=Token_RSA;self.address=address;self.sessions=sessions
        self.pul_key=pul_key;self.userdata=userdata;self.Server_DB=Server_DB;self.new_session=new_session;self.temp='';self.set_version=version
        self.jsobj:str;self.client_version:str;self.rtoken:bytes;self.session_id:str;self.platform:str;self.internal_ip:str;self.master_keys=list()
        self.protocol:str='Preliminaries';self.content_type:str;self.hmac_hash=bytes();self.Cypher_userid=bytes();self.Cypher_userpw=bytes()
        self.userid=str();self.userpw=str();self.temporary_data=list();self.pre_master_key=bytes();self.reqdata=bytes();self.master_key=bytes()
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.stream_handler)
        self.file_handler = logging.FileHandler('server.log')
        self.file_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.file_handler)
        self.new_database=dict()
        self.database=list()
        self.session_keys=dict()
        self.new_login_session=dict()
        self.login_session=dict()
        self.login_session_keys=dict()
        self.login_id=bytes();self.login_db=dict()
        self.ph=PasswordHasher()

#===================================================================================================================================#
#===================================================================================================================================#

    def service(self):
        while True:
            #try:
                try:
                    self.session_id:str=''
                    self.receive_function()
                    self.protocol_execution()
                except OSError:
                    self.c,self.addr=self.s.accept();
            #except Exception as e:
                #self.error_handler(str(e))

    def run_service(self):
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '
        self.logger.info('[ Server started at : '+self.req+' ] ')
        self.s.bind((self.set_addr,self.set_port))
        self.s.listen(0)
        self.session_checker()
        while True:
            self.c,self.addr=self.s.accept();
            self.logger.info('[ Connected with ]: '+str(self.addr))
            threading .Thread (target =self.service ).start ()

    def run(self):
        threading .Thread (target =self.run_service ).start ()

#===================================================================================================================================#
#===================================================================================================================================#

    def receive_function(self):
        self.recv_head()
        self.recv_server()
        self.json_decompress()

#===================================================================================================================================#
#===================================================================================================================================#

    def protocol_execution(self):
        if (self.content_type=='handshake' and self.protocol=='client_hello'):
            self.server_hello()
        elif (self.content_type=='handshake' and self.protocol=='client_key_exchange'):
            self.Create_master_secret()
            self.ChangeCipherSpec_Finished()
        elif (self.content_type=='client_master_secret' and self.protocol=='Sign_Up'):
            self.Sign_Up_function()
        elif (self.content_type=='client_master_secret' and self.protocol=='login'):
            self.login_function()
        elif (self.content_type=='client_master_secret' and self.protocol=='request'):
            self.response_function()
        else:
            self.error_handler('Abnormal access detected')

#===================================================================================================================================#
#===================================================================================================================================#

    def server_hello(self):
         self.token=self.L.Random_Token_generator()
         self.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                              protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                              public_key=self.pul_key,public_key_length=len(self.pul_key))
         self.send(self.jsobj_dump.encode())
         self.logger.info(str(self.addr)+' [ server hello transmission complete ] ')
         return self.jsobj_dump

    def Create_master_secret(self):
        self.master_key=self.decryption_rsa(self.prv_key,base64.b85decode(self.pre_master_key))
        self.session_creation()
        self.logger.info(str(self.addr)+' [ Master secret creation complete ] ')

    def ChangeCipherSpec_Finished(self):
        self.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                              protocol='Change_Cipher_Spec',
                                              session_id=self.session_id.decode(),session_id_length=len(self.session_id))
        self.logger.info(str(self.addr)+' [ Change Cipher Spec-Finished ] ')
        self.send(self.jsobj_dump.encode())
        self.c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    def Sign_Up_function(self):
        self.master_key=self.session_keys[self.client_session_id.encode()]
        self.Decrypt_user_data()
        self.string_check()
        self.verified_Userpw=self.pwd_hashing(self.verified_Userpw)
        if self.name_duplicate_check() == False:
            self.new_database_definition()
            self.logger.info(str(self.addr)+' [ User info update ]: '+self.UserID)
            self.Create_json_object(content_type='Sign_Up-report',platform='server',version=self.set_version,
                                        protocol='Sign_up_complete')
            self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
            self.send(self.verified_jsobj_dump)
            self.c.close()
        else:
            self.error_handler('A user with the same name already exists')

    def login_function(self):
        self.master_key=self.session_keys[self.client_session_id.encode()]
        self.Decrypt_user_data()
        self.string_check()                        
        for DB in self.database:
            if DB['user_id']==self.verified_UserID:
                #try:
                if self.ph.verify(DB['user_pw'],self.verified_Userpw):
                    self.login_session_creation(DB)
                    self.discard_session()
                    self.saver()
                    self.Create_json_object(content_type='login-report',platform='server',version=self.set_version,
                                                protocol='welcome! ',
                                                login_id=self.login_id.decode(),login_id_length=len(self.login_id))
                    self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
                    self.send(self.verified_jsobj_dump)
                    self.c.close()
                #except VerifyMismatchError: self.error_handler('The password does not match the supplied hash')
            else: self.error_handler('The user could not be found. Please proceed to sign up')

#===================================================================================================================================#
#===================================================================================================================================#

    def response_function(self):
        self.master_key=self.login_session_keys[self.client_login_id.encode()]
        self.reqdata=self.decryption_aes(base64.b85decode(self.master_secret))
        self.logger.info(str(self.addr)+' [ get request ]: '+self.reqdata.decode())
        print(self.login_session.keys())
        if self.client_login_id.encode() in self.login_session.keys():
            self.Create_json_object(content_type='server_master_secret',platform='server',version=self.set_version,login_id=self.client_login_id,
                                        protocol='response',master_secret=base64.b85encode(self.encryption_aes(self.reqdata)).decode())
            self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
            self.send(self.verified_jsobj_dump)
            self.c.close()
        else:
            self.error_handler('Invalid login ID')

#===================================================================================================================================#
#===================================================================================================================================#

    def error_handler(self,msg="None"):
        self.logger.info(str(self.addr)+' [ unexpected error ]: '+msg)
        self.Create_json_object(content_type='return_error',platform='server',version=self.set_version,
                                            protocol='error',
                                            server_error=' [ unexpected error ]: '+msg)
        self.send(self.jsobj_dump.encode())
        self.c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    def new_database_definition(self):
        if self.permission_checker()==True:
            self.database_creation(self.verified_UserID,self.verified_Userpw,'__administrator__',0)
        else: self.database_creation(self.verified_UserID,self.verified_Userpw,'__user__',1)

    def database_creation(self,user_id='user',user_pw='user1234@@!',group='__user__',permission_lv=1):
        self.new_database={'user_id':user_id,'user_pw':user_pw,'permission_lv':permission_lv,'group':group}
        self.database.append(self.new_database)
        self.logger.info(str(self.addr)+' [ New user database created ]: '+str(self.new_database))
        return self.new_database

#===================================================================================================================================#
#===================================================================================================================================#

    def session_creation(self):
        self.session_id,self.session_db=self.L.session_id_generator(set_addres=self.ip,set_internal_ip=self.internal_ip)
        self.new_session={self.session_id:self.session_db}
        self.sessions.update(self.new_session)
        self.session_keys.setdefault(self.session_id,self.master_key)
        self.logger.info(str(self.addr)+str(self.new_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+str(self.session_id))
        return self.new_session

    def login_session_creation(self,data):
        self.login_id,self.login_db=self.L.session_id_generator(set_addres=self.ip,set_internal_ip=self.internal_ip)
        self.new_login_session={self.login_id:data}
        self.new_login_session[self.login_id].update(self.login_db)
        self.login_session.update(self.new_login_session)
        self.login_session_keys.setdefault(self.login_id,self.session_keys[self.client_session_id.encode()])
        self.logger.info(str(self.addr)+str(self.new_login_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+str(self.login_id))
        return self.new_session

    def discard_session(self):
        self.logger.info(str(self.addr)+' [ Session discarded ]: '+str(self.client_session_id))
        if len(self.sessions)!=0:
            del self.sessions[self.client_session_id.encode()]
            del self.session_keys[self.client_session_id.encode()]

#===================================================================================================================================#
#===================================================================================================================================#

    def saver(self):
        self.session_setup={'login_session':self.login_session,'login_session_keys':self.login_session_keys,'database':self.database}
        with open('user_data.set','wb') as f:
            pickle.dump(self.session_setup,f)
        self.logger.info(str(self.addr)+'[ save session & database]') 

#===================================================================================================================================#
#===================================================================================================================================#

    def loader(self):
        with open('user_data.set','rb') as f:
            self.session_setup=pickle.load(f)
        self.login_session=self.session_setup['login_session']
        self.login_session_keys=self.session_setup['login_session_keys']
        self.database=self.session_setup['database']
        self.logger.info(str(self.addr)+'[ load session & database]')
        
#===================================================================================================================================#
#===================================================================================================================================#

    def recv_head(self):
        #try:
        self.head=self.c.recv(4)
        self.head=int(str(struct.unpack("I",self.head)).split(',')[0].split('(')[1])
        self.logger.info(str(self.addr)+' [ Header received ]: '+str(self.head))
        self.ip=str(self.addr).split("'")[1]
        return self.head,self.c,self.addr
        #except:
            #print('An unexpected error occurred')

    def recv_server(self):
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
        self.logger.info(str(self.addr)+' [ Get requested ]: '+self.session_id)
        return self.recv_datas
        #except:
            #print('An unexpected error occurred')

#===================================================================================================================================#
#===================================================================================================================================#

    def merge_data(self,data:bytes):
        self.body=base64.b85encode(data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        self.logger.info(str(self.addr)+' [ Transmission data size ]: '+str(len(self.body)))
        return self.send_data

    def send(self,data:str):
        self.c.send(self.merge_data(data))
        self.logger.info(str(self.addr)+' [ response complete ] ')


#===================================================================================================================================#
#===================================================================================================================================#

    def json_decompress(self):
        self.recv_datas = base64.b85decode(self.recv_datas).decode()
        self.logger.info(str(self.addr) + str(self.recv_datas))
        try:
            self.jsobj = json.loads(self.recv_datas)
        except json.decoder.JSONDecodeError as e:
            self.jsobj = json.loads(self.recv_datas[:len(self.recv_datas) - 80])
            self.hmac_hash = base64.b85decode((self.recv_datas[len(self.recv_datas) - 80:].encode()))
            self.logger.info(str(self.addr) + ' [ hmac hash scanned ]')

        self._assign_variables()

    def _assign_variables(self):
        self.client_version = self.jsobj["version"]
        self.rtoken = self.jsobj['body']['random_token']
        self.client_session_id = self.jsobj['body']['session-id']
        self.client_login_id = self.jsobj['body']['login-id']
        self.platform = self.jsobj["platform"]
        self.internal_ip = self.jsobj["addres"]
        self.protocol = self.jsobj['body']["protocol"]
        self.content_type = self.jsobj["content-type"]
        self.Cypher_userid = self.jsobj['body']["userid"]
        self.Cypher_userpw = self.jsobj['body']['userpw']
        self.pre_master_key = self.jsobj['body']['pre_master_key']
        self.master_secret = self.jsobj['body']['master_secret']
        self.logger.info(str(self.addr) + ' [ variable assignment done ] ')

    def Create_json_object(self,content_type=None,platform=None,version=None,
                                        protocol=None,random_token=None,random_token_length=None,
                                        public_key=None,public_key_length=None,server_error=None,
                                        session_id=None,session_id_length=None,master_secret=None,
                                        login_id=None,login_id_length=None):
        self.jsobj={
            'content-type':content_type, 
            'platform':platform,
            'version':version,
            'body':{'protocol':protocol,
                        'random_token':random_token,
                        'random_token_length':random_token_length,
                        'session-id':session_id,
                        'session-id_length':session_id_length,
                        'login-id':login_id,
                        'login-id_length':login_id_length,
                        'public-key':public_key,
                        'public-key_length':public_key_length,
                        'master_secret':master_secret,
                        'server_error':server_error
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        self.logger.info(str(self.addr)+str(self.jsobj_dump))
        return self.jsobj_dump

#===================================================================================================================================#
#===================================================================================================================================#

    def Decrypt_user_data(self):
        self.userid=self.decryption_aes(base64.b85decode(self.Cypher_userid))
        self.userpw=self.decryption_aes(base64.b85decode(self.Cypher_userpw))
        return self.userid,self.userpw

#===================================================================================================================================#
#===================================================================================================================================#

    def hmac_cipher(self,data:bytes):
        self.hmac_data=base64.b85encode(hmac.digest(self.master_key,data,blake2b))
        self.verified_data=data+self.hmac_data
        self.logger.info(str(self.addr)+' [ hmac applied ]: '+str(self.hmac_data))
        return self.verified_data


    def encryption_aes(self,data:bytes):
         self.data=base64.b85encode(data)
         self.send_data=bytes()
         cipher_aes = AES.new(self.master_key, AES.MODE_EAX)
         ciphertext, tag = cipher_aes.encrypt_and_digest(self.data)
         self.send_data= cipher_aes.nonce+ tag+ ciphertext
         return self.send_data

#===================================================================================================================================#
#===================================================================================================================================#

    def decryption_rsa(self,set_prv_key:bytes,encrypt_data:bytes):
        private_key = RSA.import_key(set_prv_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        self.decrypt_data=base64.b85decode(cipher_rsa.decrypt(encrypt_data))
        self.logger.info(str(self.addr)+' [ key decryption complete ] ')
        return self.decrypt_data

    def decryption_aes(self,set_data):
        nonce=set_data[:16]
        tag=set_data[16:32]
        ciphertext =set_data[32:-1]+set_data[len(set_data)-1:]
        cipher_aes = AES.new(self.master_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self.decrypt_data=base64.b85decode(data)
        self.logger.info(str(self.addr)+' [ data decryption complete ] ')
        return self.decrypt_data

#===================================================================================================================================#
#===================================================================================================================================#

    def name_duplicate_check(self):
        if len(self.database) != 0:
            for DB in self.database:
                return DB['user_id']==self.verified_UserID
        else:
            return False

    def Session_credentials(self):
        if (self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b) and self.session_db[self.session_id.encode()]['User addres']==self.ip):
            self.logger.info(str(self.addr)+' [ Session Credentials Completed ]: '+str(self.session_id))
            return True
        else:
            self.error_handler('Message tampering confirmed')
            return False

    def permission_checker(self):
        if (self.ip=='127.0.0.1' and self.verified_UserID=='administrator' or self.verified_UserID=='admin'):
            return True
        else:
            return False

    def session_checker(self):
        self.dir=os.listdir(os.getcwd())
        if ('user_data.set' in self.dir):
            self.loader()
            return True

    def string_check(self):
        self.UserID=self.userid.decode()
        self.Userpwrd=self.userpw.decode()
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if (len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd):
                self.verified_UserID=self.UserID
                self.verified_Userpw=self.Userpwrd
                print(self.verified_UserID,self.verified_Userpw)
                return self.verified_UserID,self.verified_Userpw
            else:
                self.error_handler("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            self.error_handler("Name cannot contain spaces or special characters")

    def pwd_hashing(self,pwd):
        while True:
            temp=self.ph.hash(pwd)
            if (self.ph.verify(temp,pwd) and self.ph.check_needs_rehash(temp)!=True):
                break
        self.logger.info(str(self.addr)+' [ Password hashing success ] ')
        return temp

#===================================================================================================================================#
#===================================================================================================================================#