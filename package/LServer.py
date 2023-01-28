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
import re,base64,requests,struct,hmac,logging,pickle,secrets
from multiprocessing import Process

__all__=['Server']


set_port:int=9997;set_addr:str='0.0.0.0';
s=socket();
ip:str=str();Token:bytes=bytes();Token_data:dict=dict();Token_DB:dict=dict()
rdata:str='';platform:str='shell';head='';c='';addr='';Token_RSA:bytes=bytes();RSA_Key:dict=Longinus().Create_RSA_key()
address=list();sessions:dict=dict();prv_key:str=open(RSA_Key['private_key']).read();pul_key:str=open(RSA_Key['public_key']).read();userdata:bytes=bytes()
Server_DB:dict=dict();new_session:dict=dict()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
file_handler = logging.FileHandler('server.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
L= Longinus()

class Server:
    def __init__(self,version='0.4.6',port=set_port,addres=set_addr):
        self.set_port=port;self.set_addr=addres;self.cipherdata=bytes();self.decrypt_data=bytes()
        self.s=s;self.pul_key=pul_key;self.set_version=version
        self.logger=logger

    def run(self):
        threading .Thread (target =self.run_service ).start ()

    def run_service(self):
        self.bind_address()
        self.listen()
        while True:
            self.access_information=self.accept_connection()
            self.N=self.Network(self.access_information)
            threading .Thread (target =self.handler_connection ).start ()

    def bind_address(self):
        self.req = requests.get("http://ipconfig.kr")
        self.req = str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.logger.info('[ Server started at : ' + self.req + ' ] ')
        self.s.bind((self.set_addr, self.set_port))

    def listen(self,max_listen=0):
        self.s.listen(max_listen)

    def accept_connection(self):
        self.c, self.addr = self.s.accept()
        self.ip=str(self.addr).split("'")[1]
        self.logger.info('[ Connected with ]: ' + str(self.addr))
        return self.c, self.addr, self.ip

    def handler_connection(self):
        self.receive_function()
        self.protocol_execution()

    def receive_function(self):
        self.N.recv_head()
        self.N.recv()
        self.N.json_decompress()

    def protocol_execution(self):
        if (self.N.content_type == 'handshake' and self.N.protocol == 'client_hello'):
            self.SSLConnection(self.access_information).server_hello()
        elif (self.N.content_type == 'handshake' and self.N.protocol == 'client_key_exchange'):
            self.SSLConnection(self.access_information).create_master_secret()
            self.SSLConnection(self.access_information).change_cipher_spec_finished()
        elif (self.N.content_type == 'client_master_secret' and self.N.protocol == 'Sign_Up'):
            self.HANDLERS().sign_up_handler()
        elif (self.N.content_type == 'client_master_secret' and self.N.protocol == 'login'):
            self.HANDLERS().login_handler()
        elif (self.content_type == 'client_master_secret' and self.N.protocol == 'request'):
            self.HANDLERS().request_handler()
        else:
            self.ERROR().error_handler('Abnormal access detected')

#===================================================================================================================================#
#===================================================================================================================================#

    class Network:
        def __init__(self,access_information):
            self.head=''
            self.c=access_information[0]
            self.addr=access_information[1]
            self.ip=access_information[2]
            self.head = self.c.recv
            self.recv_datas=''
            self.logger=logger

        def recv_head(self):
            self.head = self.c.recv(4)
            self.head = int(struct.unpack("I", self.head)[0])
            self.logger.info(f'{self.addr} [Header received]: {self.head}')
            return self.head

        def recv(self):
            self.recv_datas = bytes()
            if self.head < 2048:
                self.recv_datas = self.c.recv(self.head)
            else:
                self.recv_datas = bytearray()
                for i in range(int(self.head / 2048)):
                    self.recv_datas += self.c.recv(2048)
                    self.logger.info(f'{self.addr} [Receiving data]: {2048 * i / self.head * 100}%')
                self.logger.info(f'{self.addr} [Receiving data]: 100%')
            self.logger.info(f'{self.addr} [Data received]: {len(self.recv_datas)} bytes')
            return self.recv_datas

        def send(self, data: bytes):
            head = struct.pack("I", len(data))
            self.c.sendall(head + data)
            self.logger.info(f'{self.addr} [Data sent]: {len(data)} bytes')

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

    class SSLConnection:
        def __init__(self,access_information):
            self.set_addr = Server().set_addr
            self.set_port = Server().set_port
            self.master_key=''
            self.c=access_information[0]
            self.addr=access_information[1]
            self.set_version=Server().set_version
            self.SN=Server().Network(access_information)
            self.logger=logger

        def server_hello(self):
            self.token=Longinus().Random_Token_generator()
            self.SN.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                                protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                                public_key=Server().pul_key,public_key_length=len(Server().pul_key))
            self.SN.send(self.SN.jsobj_dump.encode())
            self.logger.info(str(self.addr)+' [ server hello transmission complete ] ')

        def Create_master_secret(self):
            self.master_key=Server().Crypto()._decrypt_rsa(self.prv_key,base64.b85decode(self.pre_master_key))
            self.session_id=Server().SessionManager().session_creation()
            self.logger.info(str(self.addr)+' [ Master secret creation complete ] ')

        def ChangeCipherSpec_Finished(self):
            self.SN.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                                protocol='Change_Cipher_Spec',
                                                session_id=self.session_id.decode(),session_id_length=len(self.session_id))
            self.logger.info(str(self.addr)+' [ Change Cipher Spec-Finished ] ')
            self.SN.send(self.SN.jsobj_dump.encode())
            self.c.close()

        def Master_key_setting(self):
            if self.SN.client_session_id !=None:
                self.master_key=Server().UserManagement().session_keys[self.SN.client_session_id.encode()]
            elif self.SN.client_login_id !=None:
                self.master_key=Server().UserManagement().login_session_keys[self.SN.client_session_id.encode()]
            return self.master_key
#===================================================================================================================================#
#===================================================================================================================================#

    class HANDLERS:
        def __init__(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.set_version = Server().set_version
            self.userid,self.userpw=Server().Crypto().Decrypt_user_data(self.Network().Cypher_userid,self.Network().Cypher_userpw)
            self.User=Server().User(self.userid,self.userpw)
            self.verified_Userid,self.verified_Userpw,=self.User.verify_credentials()
            self.ip=Server().ip
            self.addr=Server().addr
            self.SN=Server().Network()
            self.logger=logger

        def Sign_Up_handler(self):
            self.verified_Userpw=self.User.pwd_hashing(self.verified_Userpw)
            if Server().SessionManager().sessions[self.SN.client_session_id.encode()]['User addres']==self.ip:
                Server().DBManagement().new_database_definition(self.verified_Userid,self.verified_Userpw)
                self.logger.info(str(self.addr)+' [ User info update ]: '+self.verified_Userid)
                self.SN.Create_json_object(content_type='Sign_Up-report',platform='server',version=self.set_version,
                                            protocol='Sign_up_complete')
                self.verified_jsobj_dump=Server().Crypto().hmac_cipher(self.SN.jsobj_dump.encode())
                self.SN.send(self.verified_jsobj_dump)
                Server().c.close()

        def login_handler(self):                 
            for DB in self.database:
                if DB['user_id']==self.verified_Userid:
                    #try:
                    print(DB['user_pw'])
                    print(self.verified_Userpw)
                    if self.ph.verify(DB['user_pw'],self.verified_Userpw):
                        self.login_id=Server().SessionManager().login_session_creation(DB)
                        Server().SessionManager().discard_session(self.SN.client_session_id.encode())
                        Server().SessionManager().saver()
                        self.SN.Create_json_object(content_type='login-report',platform='server',version=self.set_version,
                                                    protocol='welcome! ',
                                                    login_id=self.login_id,login_id_length=len(self.login_id))
                        self.verified_jsobj_dump=Server().Crypto().hmac_cipher(self.SN.jsobj_dump.encode())
                        self.SN.send(self.verified_jsobj_dump)
                        Server().c.close()
                    #except VerifyMismatchError: Server().ERROR().error_handler('The password does not match the supplied hash')
                else: Server().ERROR().error_handler('The user could not be found. Please proceed to sign up')

        def request_handler(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.reqdata=self.decryption_aes(base64.b85decode(self.master_secret))
            self.logger.info(str(self.addr)+' [ get request ]: '+self.reqdata.decode())
            print(self.login_session.keys())
            if self.SN.client_login_id.encode() in self.login_session.keys():
                self.SN.Create_json_object(content_type='server_master_secret',platform='server',version=self.set_version,login_id=self.client_login_id,
                                            protocol='response',master_secret=base64.b85encode(self.encryption_aes(self.reqdata)).decode())
                self.verified_jsobj_dump=self.hmac_cipher(self.SN.jsobj_dump.encode())
                self.SN.send(self.verified_jsobj_dump)
                Server().c.close()
            else:
                Server().ERROR().error_handler('Invalid login ID')

    class ERROR:
        def error_handler(self,msg="None"):
            self.logger=logger
            self.SN=Server().Network()
            self.logger.info(str(Server().addr)+' [ unexpected error ]: '+msg)
            self.SN.Create_json_object(content_type='return_error',platform='server',version=Server().set_version,
                                                protocol='error',
                                                server_error=' [ unexpected error ]: '+msg)
            self.SN.send(self.SN.jsobj_dump.encode())
            Server().c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    class DBManagement:
        def __init__(self):
            self.logger=logger
            self.database = []

        def new_database_definition(self,verified_UserID,verified_Userpw, group='__user__', permission_lv=1):
            self.verified_Userpw=verified_Userpw
            self.verified_UserID=verified_UserID
            self.group=group
            self.permission_lv=permission_lv
            if Server().User()._permission_checker() == True:
                self.group='__administrator__'
            self.database_creation()

        def database_creation(self):
            new_database = {'user_id': self.verified_UserID, 'user_pw': self.verified_Userpw, 'permission_lv': self.permission_lv, 'group': self.group}
            self.database.append(new_database)
            self.logger.info(f'[ New user database created ]: {new_database}')
            return new_database

    class SessionManager:
        def __init__(self):
            self.sessions = {}
            self.session_keys = {}
            self.login_sessions = {}
            self.login_session_keys = {}
            self.TokenDB={}
            self.logger=logger

        def session_creation(self, ip, internal_ip):
            session_id, session_db = self.session_generator(ip, internal_ip)
            self.sessions[session_id] = session_db
            self.session_keys[session_id] = self.master_key
            self.logger.info(f'{ip} Session assignment complete: {session_id}')
            return session_id

        def login_session_creation(self, data,ip, internal_ip):
            login_id, login_db = self.session_generator(ip, internal_ip)
            login_session = {login_id: {**data, **login_db}}
            self.login_sessions.update(login_session)
            self.login_session_keys[login_id] = self.session_keys[self.session_id]
            self.logger.info(f'{ip} login Session assignment complete: {login_id}')
            return login_id

        def session_generator(self, ip, internal_ip):
            token = base64.b85encode(secrets.token_bytes(16)).decode()
            now = datetime.now().timestamp()
            now_after = now + datetime.timedelta(days=35)
            token_data = {'ip': ip, 'internal_ip': internal_ip, 'timestamp': now, 'validity': now_after}
            self.TokenDB[token] = token_data
            return token, token_data

        def discard_session(self, session_id):
            self.logger.info('Session discarded: {session_id}')
            if self.sessions:
                del self.sessions[session_id]
                del self.session_keys[session_id]

        def validate_session(self):
            pass

        def saver(self):
            self.save_session_and_database(self.login_sessions,self.login_session_keys,self.database)

        def loader(self):
            self.login_sessions, self.login_session_keys, self.database = self.load_session_and_database()

        def save_session_and_database(self, sessions, session_keys, database):
            with open('user_data.set', 'wb') as f:
                pickle.dump({'login_sessions': sessions, 'login_session_keys': session_keys, 'database': database}, f)
            self.logger.info('[ save session & database]')

        def load_session_and_database(self):
            with open('user_data.set', 'rb') as f:
                session_setup = pickle.load(f)
            return session_setup['login_sessions'], session_setup['login_session_keys'], session_setup['database']

#===================================================================================================================================#
#===================================================================================================================================#

    class Crypto:
        def __init__(self, master_key):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.ph = PasswordHasher()
            self.logger=logger

        def Decrypt_user_data(self,Cypher_userid,Cypher_userpw):
            self.userid=self._decrypt_aes(base64.b85decode(self.Cypher_userid))
            self.userpw=self.v(base64.b85decode(self.Cypher_userpw))
            return self.userid,self.userpw

        def hmac_cipher(self, data: bytes):
            hmac_data = base64.b85encode(hmac.digest(self.master_key, data, blake2b))
            verified_data = data + hmac_data
            return verified_data

        def _encrypt_aes(self, data: bytes):
            data = base64.b85encode(data)
            send_data = bytes()
            cipher_aes = AES.new(self.master_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            send_data = cipher_aes.nonce + tag + ciphertext
            return send_data

        def _decrypt_rsa(self, set_prv_key: bytes, encrypt_data: bytes):
            private_key = RSA.import_key(set_prv_key)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypt_data = base64.b85decode(cipher_rsa.decrypt(encrypt_data))
            return decrypt_data

        def _decrypt_aes(self, set_data):
            nonce = set_data[:16]
            tag = set_data[16:32]
            ciphertext = set_data[32:-1] + set_data[len(set_data)-1:]
            cipher_aes = AES.new(self.master_key,AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
            decrypt_data = base64.b85decode(data)
            return decrypt_data

    class User:
        def __init__(self, userid, userpw):
            self.userid = userid
            self.userpw = userpw
            self.ph = PasswordHasher()
            self.verified_UserID=''
            self.verified_Userpw=''
            self.addr=Server().addr
            self.logger=logger

        def verify_credentials(self):
            self.UserID = self.userid.decode()
            self.Userpwrd = self.userpw.decode()
            if not self._verify_userid():
                Server().ERROR().error_handler("Name cannot contain spaces or special characters")
            elif not self._verify_userpw():
                Server().ERROR().error_handler("Your password is too short or too easy. Password must be at least 8 characters and contain numbers, English characters and symbols. Also cannot contain whitespace characters.")
            else:
                self.verified_UserID = self.UserID
                self.verified_Userpw = self.Userpwrd
                if not self._name_duplicate_check():
                    Server().ERROR().error_handler("This user already exists.")
                elif not self._session_credentials():
                    Server().ERROR().error_handler("Session Credentials check failed.")
                else:
                    print(self.verified_UserID, self.verified_Userpw)
                    return self.verified_UserID, self.verified_Userpw

        def _verify_userid(self):
            if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
                return True
            return False

        def _verify_userpw(self):
            if (len(self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd):
                return True
            return False

        def _name_duplicate_check(self):
            if len(self.database) != 0:
                for DB in self.database:
                    return DB['user_id']==self.verified_UserID
            else:
                return False

        def _session_credentials(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            if (self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b)):
                logger.info(str(self.addr)+' [ Session Credentials Completed ]: '+str(self.session_id))
                return True
            else:
                return False

        def _permission_checker(self):
            if (self.self.Network().ip=='127.0.0.1' and self.verified_UserID=='administrator' or self.verified_UserID=='admin'):
                return True
            else:
                return False

        def _session_checker(self):
            self.dir=os.listdir(os.getcwd())
            if ('user_data.set' in self.dir):
                self.loader()
                return True
            else:
                return False

        def pwd_hashing(self,pwd):
            while True:
                temp=self.ph.hash(pwd)
                if (self.ph.verify(temp,pwd) and self.ph.check_needs_rehash(temp)!=True):
                    break
            return temp
#===================================================================================================================================#
#===================================================================================================================================#

Server().run()