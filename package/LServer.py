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
        self.s=s;self.ip=ip;self.session_id=Token;self.Login_list='Login_list';self.body=bytes();self.temp_db=None;self.prv_key=prv_key
        self.session_id_data=Token_data;self.session_db=Token_DB;self.rdata=rdata;self.platform=platform;self.pul_key=pul_key
        self.head=head;self.c=c;self.addr=addr;self.session_id_RSA=Token_RSA;self.address=address;self.sessions=sessions
        self.pul_key=pul_key;self.userdata=userdata;self.Server_DB=Server_DB;self.new_session=new_session;self.temp=''
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

#===================================================================================================================================#
#===================================================================================================================================#

    def service(self):
        while True:
            try:
            #try:
                self.session_id:str=''
                self.receive_function()
                self.protocol_execution()
            #except Exception as e:
                #self.error_handler(str(e).encode())
            except OSError:
                self.c,self.addr=self.s.accept();

    def run_service(self):
        self.session_checker()
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '
        self.logger.info('[ Server started at : '+self.req+' ] ')
        self.s.bind((self.set_addr,self.set_port))
        self.s.listen(0)
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

    def server_hello(self,set_version='0.4.4'):
         self.token=self.L.Random_Token_generator()
         self.Create_json_object(content_type='handshake',platform='server',version=set_version,
                                              protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                              public_key=self.pul_key,public_key_length=len(self.pul_key))
         self.send(self.jsobj_dump.encode())
         self.logger.info(str(self.addr)+' [ server hello transmission complete ] ')
         return self.jsobj_dump

    def Create_master_secret(self):
        self.master_key=self.decryption_rsa(self.prv_key,base64.b85decode(self.pre_master_key))
        self.master_keys.append(self.master_key)
        self.logger.info(str(self.addr)+' [ Master secret creation complete ] ')

    def ChangeCipherSpec_Finished(self,set_version='0.4.4'):
        self.session_creation(None)
        self.Create_json_object(content_type='handshake',platform='server',version=set_version,
                                              protocol='Change_Cipher_Spec',
                                              session_id=self.session_id.decode(),session_id_length=len(self.session_id))
        self.logger.info(str(self.addr)+' [ Change Cipher Spec-Finished ] ')
        self.send(self.jsobj_dump.encode())
        self.c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    def Sign_Up_function(self):
        if self.Check_master_key()==True:
            self.Decrypt_user_data()
            self.string_check()
            if self.duplicate_inspection() == True:
                self.new_database_definition()
                self.session_creation(None)
                self.logger.info(str(self.addr)+' [ User info update ]: '+self.UserID)
                self.Create_json_object(content_type='Sign_Up-report',platform='server',version='0.4.4',
                                            protocol='Sign_up_complete')
                self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
                self.send(self.verified_jsobj_dump)
                self.c.close()

    def login_function(self):
        if self.Check_master_key()==True:
            self.Decrypt_user_data()                            
            for DB in self.database:
                if DB['user_id']==self.temporary_data[0]:
                    if PasswordHasher().verify(DB['user_pw'],self.temporary_data[1])==True:
                        self.session_creation(DB)
                        self.saver()
                        self.Create_json_object(content_type='login-report',platform='server',version='0.4.4',
                                                    protocol='welcome! ',session_id=self.session_id.decode())
                        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
                        self.send(self.verified_jsobj_dump)
                        self.c.close()
                    else: self.error_handler('The password does not match the supplied hash')
                else: self.error_handler('The user could not be found. Please proceed to sign up')

#===================================================================================================================================#
#===================================================================================================================================#

    def response_function(self,version='0.4.4'):
        self.reqdata=self.decryption_aes(base64.b85decode(self.master_secret))
        self.logger.info(str(self.addr)+' [ get request ]: '+self.reqdata.decode())
        self.Check_Session_key()
        self.Create_json_object(content_type='server_master_secret',platform='server',version='0.4.4',
                                    protocol='response',master_secret=base64.b85encode(self.encryption_aes(self.reqdata)).decode())
        self.verified_jsobj_dump=self.hmac_cipher(self.jsobj_dump.encode())
        self.send(self.verified_jsobj_dump)
        self.c.close()
        #else:
            #self.error_handler('An attempt to sign up from another region was detected during member registration.')

#===================================================================================================================================#
#===================================================================================================================================#

    def error_handler(self,msg="None"):
        self.logger.info(str(self.addr)+' [ unexpected error ]: '+msg)
        self.Create_json_object(content_type='return_error',platform='server',version='0.4.4',
                                            protocol='error',
                                            server_error=' [ unexpected error ]: '+msg)
        self.send(self.jsobj_dump.encode())
        self.c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    def new_database_definition(self):
        if self.permission_checker()==True:
            self.database_creation(self.verified_UserID,self.verified_Userpw,'__administrator__',0)
        else:
            self.database_creation(self.verified_UserID,self.verified_Userpw,'__user__',1)

    def database_creation(self,user_id='user',user_pw='user1234@@!',group='__user__',permission_lv=1):
        self.new_database={'user_id':user_id,'user_pw':user_pw,'permission_lv':permission_lv,'group':group}
        self.database.append(self.new_database)
        self.logger.info(str(self.addr)+' [ New user database created ]: '+str(self.new_database))
        self.temporary_data=list()
        return self.new_database

#===================================================================================================================================#
#===================================================================================================================================#

    def session_creation(self,data):
        self.session_id,self.session_db=self.L.session_id_generator(set_addres=self.ip,set_internal_ip=self.internal_ip)
        self.new_session={self.session_id:data}
        self.new_session[self.session_id].update(self.session_db)
        self.sessions.update(self.new_session)
        self.session_keys.setdefault(self.session_id,self.master_key)
        self.logger.info(str(self.addr)+str(self.new_session))
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+str(self.session_id))
        return self.new_session

#===================================================================================================================================#
#===================================================================================================================================#

    def saver(self):        
        self.Sessions_saver()
        self.DB_saver()
        self.setting_saver()

#===================================================================================================================================#
#===================================================================================================================================#

    def Sessions_saver(self):
        self.logger.info(str(self.addr)+'[ Saving Sessions ] ')
        with open('Sessions','wb') as f:
            pickle.dump(self.sessions,f)
        with open('Session_keys','wb') as f:
            pickle.dump(self.session_keys,f)

    def DB_saver(self):
        self.logger.info(str(self.addr)+'[ Saving DB ] ')
        with open('server_DB.DB','wb') as f:
            pickle.dump(self.database,f) 

    def setting_saver(self):
        self.setting={'addr':self.set_addr,'port':self.set_port}
        self.logger.info(str(self.addr)+'[ Saving setting ] ')
        with open('setting.set','wb') as f:
            pickle.dump(self.setting,f)

#===================================================================================================================================#
#===================================================================================================================================#

    def loader(self):
        self.Sessions_loader()
        self.DB_loader()
        self.setting_loader()
        
#===================================================================================================================================#
#===================================================================================================================================#

    def Sessions_loader(self):
        with open('Sessions','rb') as f:
            self.sessions=pickle.load(f)
        with open('Session_keys','rb') as f:
            self.session_keys=pickle.load(f)
        self.logger.info(str(self.addr)+'[ load Sessions ]')

    def DB_loader(self):
        with open('server_DB.DB','rb') as f:
            self.database=pickle.load(f)
        self.logger.info(str(self.addr)+'[ load DB ]')  

    def setting_loader(self):
        with open('setting.set','rb') as f:
            self.setting=pickle.load(f)
        self.set_addr=self.setting['addr']
        self.set_port=self.setting['port']
        self.logger.info(str(self.addr)+'[ load setting ]')

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
        self.recv_datas=base64.b85decode(self.recv_datas).decode()
        self.logger.info(str(self.addr)+str(self.recv_datas))
        try:
            self.jsobj = json.loads(self.recv_datas)
            self.client_version=self.jsobj["version"]
            self.rtoken=self.jsobj['body']['random_token']
            self.client_session_id=self.jsobj['body']['session_id']
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
            self.client_session_id=self.jsobj['body']['session_id']
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

#===================================================================================================================================#
#===================================================================================================================================#

    def Decrypt_user_data(self):
        self.userid=self.decryption_aes(base64.b85decode(self.Cypher_userid))
        self.userpw=self.decryption_aes(base64.b85decode(self.Cypher_userpw))
        self.temporary_data=[self.userid.decode(),self.userpw.decode()]
        return self.temporary_data

#===================================================================================================================================#
#===================================================================================================================================#

    def hmac_cipher(self,data:bytes):
        self.hmac_data=base64.b85encode(hmac.digest(self.master_key,data,blake2b))
        self.verified_data=data+self.hmac_data
        self.logger.info(str(self.addr)+' [ hmac applied ]: '+str(self.hmac_data))
        return self.verified_data


    def encryption_aes(self,data:bytes):
         self.data=base64.b85encode(data)
         self.send_data=bytes
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

    def Check_master_key(self):
        self.pre_master_key=self.decryption_rsa(self.prv_key,base64.b85decode(self.pre_master_key))
        for m in self.master_keys:
            if m==self.pre_master_key:
                self.master_key=m
                return True

    def Check_Session_key(self):
        for s,m in self.session_keys:
            if s == self.client_session_id:
                self.master_key=m
                return self.master_key

    def duplicate_inspection(self):
        if len(self.database) != 0:
            for DB in self.database:
                if (DB['user_id']!=self.verified_UserID):
                    return True
                else:
                    self.error_handler('Rename')
                    return False
        else:
            return True

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
        if ('Sessions' in self.dir and 'Session_keys' in self.dir):
            self.loader()
            return True

    def string_check(self):
        self.UserID=self.temporary_data[0]
        self.Userpwrd=self.temporary_data[1]
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if (len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd):
                self.verified_Userpw=self.L.pwd_hashing(self.Userpwrd)
                self.logger.info(str(self.addr)+' [ PasswordHashing complete ]: '+str(PasswordHasher().verify(self.verified_Userpw,self.Userpwrd)))
                self.verified_UserID=self.UserID
                self.temporary_data=[self.verified_UserID,self.verified_Userpw]
                return self.temporary_data
            else:
                self.error_handler("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
        else:
            self.error_handler("Name cannot contain spaces or special characters")

#===================================================================================================================================#
#===================================================================================================================================#

Server().run()

