from LonginusPyPiAlpha import Longinus
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import subprocess,threading,sys,os,json
from socket import *
from getpass import *
from datetime import datetime
from datetime import timedelta
from asyncio import *
from hashlib import blake2b
from argon2 import PasswordHasher
import re,base64,requests,struct,hmac,logging,pickle,secrets
from multiprocessing import Process

__all__=['Server']


set_port:int=9997;set_addr:str='0.0.0.0';

RSA_Key:dict=Longinus().Create_RSA_key()

prv_key:str=open(RSA_Key['private_key']).read();pul_key:str=open(RSA_Key['public_key']).read()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
file_handler = logging.FileHandler('server.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class Server:
    s=socket()
    c=''
    addr=''
    ip=''
    sessions = {}
    session_keys = {}
    login_sessions = {}
    login_session_keys = {}
    database = {}
    json_obj=''
    def __init__(self,version='0.4.6',port=set_port,addres=set_addr):
        self.set_port=port;self.set_addr=addres;self.cipherdata=bytes();self.decrypt_data=bytes()
        self.pul_key=pul_key;self.set_version=version
        self.logger=logger;

    def run(self):
        self.bind_address()
        self.listen()
        self.run_service()

    def run_service(self):
        while True:
            self.N=self.Network()
            self.accept_connection()
            self.handler_connection()

    def bind_address(self):
        self.req = requests.get("http://ipconfig.kr")
        self.req = str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.logger.info('[ Server started at : ' + self.req + ' ] ')
        self.s.bind((self.set_addr, self.set_port))

    def listen(self,max_listen=0):
        self.s.listen(max_listen)

    def accept_connection(self):
        print('accept_connection')
        Server.c, Server.addr = Server.s.accept()
        Server.ip=str(Server.addr).split("'")[1]
        self.logger.info('[ Connected with ]: ' + str(Server.addr))
        return Server.c, Server.addr, Server.ip

    def handler_connection(self):
        while True:
            self.receive_function()
            self.protocol_execution()

    def receive_function(self):
        print('receive_function')
        self.N.recv_head()
        self.recv_data=self.N.recv()
        self.obj=self.DATA(self.recv_data)
        Server.json_obj=self.obj.json_decompress()

    def protocol_execution(self):
        print('protocol_execution')
        if (Server.json_obj['content-type'] == 'handshake' and Server.json_obj['body']['protocol'] == 'client_hello'):
            self.SSLConnection('').server_hello()
        elif (Server.json_obj['content-type'] == 'handshake' and Server.json_obj['body']['protocol'] == 'client_key_exchange'):
            self.session_id,self.master_key=self.SSLConnection('').Create_master_secret()
            self.SSLConnection('').ChangeCipherSpec_Finished(self.session_id)
        elif (Server.json_obj['content-type'] == 'client_master_secret' and Server.json_obj['body']['protocol'] == 'Sign_Up'):
            self.HANDLERS().sign_up_handler()
        elif (Server.json_obj['content-type'] == 'client_master_secret' and Server.json_obj['body']['protocol'] == 'login'):
            self.HANDLERS().login_handler()
        elif (Server.json_obj['content-type'] == 'client_master_secret' and Server.json_obj['body']['protocol'] == 'request'):
            self.HANDLERS().request_handler()
        else:
            self.ERROR().error_handler('Abnormal access detected')

#===================================================================================================================================#
#===================================================================================================================================#

    class Network:
        def __init__(self):
            self.head=''
            self.recv_datas=''
            self.set_version=Server().set_version
            self.logger=logger

        def recv_head(self):
            try:
                self.head = Server.c.recv(4)
                self.head = int(struct.unpack("I", self.head)[0])
                self.logger.info(f'{Server.addr} [Header received]: {self.head}')
            except:
                Server().accept_connection()
                return self.head

        def recv(self):
            self.recv_datas = bytes()
            if self.head < 2048:
                self.recv_datas = Server.c.recv(self.head)
            else:
                self.recv_datas = bytearray()
                for i in range(int(self.head / 2048)):
                    self.recv_datas += Server.c.recv(2048)
                    self.logger.info(f'{Server.addr} [Receiving data]: {2048 * i / self.head * 100}%')
                self.logger.info(f'{Server.addr} [Receiving data]: 100%')
            self.logger.info(f'{Server.addr} [Data received]: {len(self.recv_datas)} bytes')
            print(self.recv_datas)
            return self.recv_datas

        def send(self, data: bytes):
            head = struct.pack("I", len(data))
            Server.c.sendall(head + data)
            self.logger.info(f'{Server.addr} [Data sent]: {len(data)} bytes')

    class DATA:
        def __init__(self,data=''):
            self.data=data
            self.jsobj=''
            self.logger=logger

        def json_decompress(self):
            # try:
                self.data = base64.b85decode(self.data).decode()
                self.logger.info(str(Server.addr) + str(self.data))
                try:
                    self.jsobj = json.loads(self.data)
                except json.decoder.JSONDecodeError as e:
                    self.jsobj = json.loads(self.data.split('.')[0])
                    self.hmac_hash = base64.b85decode(self.data.split('.')[1])
                    print(self.jsobj,'\n')
                    print(self.hmac_hash,'\n')
                    self.logger.info(str(Server.addr) + ' [ hmac hash scanned ]')
                return self.jsobj
            # except Exception:
            #     self.send('thank you! Server test was successful thanks to you, This message is a temporary message written to convey thanks to you, and it is a disclaimer that the server is operating normally.')

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
            self.logger.info(str(Server.addr)+str(self.jsobj_dump))
            return self.jsobj_dump


#===================================================================================================================================#
#===================================================================================================================================#

    class SSLConnection:
        def __init__(self,set_version=''):
            self.master_key=''
            self.set_version=set_version
            self.SD=Server().DATA()
            self.SN=Server().Network()
            self.logger=logger

        def server_hello(self):
            self.token=Longinus().Random_Token_generator()
            self.SD.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                                protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                                public_key=Server().pul_key,public_key_length=len(Server().pul_key))
            self.SN.send(base64.b85encode(self.SD.jsobj_dump.encode()))
            self.logger.info(str(Server.addr)+' [ server hello transmission complete ] ')

        def Create_master_secret(self):
            self.master_key=Server().Crypto()._decrypt_rsa(prv_key,base64.b85decode(Server.json_obj['body']['pre_master_key']))
            self.session_id=Server().SessionManager().session_creation(self.master_key,Server.ip,Server.json_obj['addres'])
            self.logger.info(str(Server.addr)+' [ Master secret creation complete ] ')
            return self.session_id,self.master_key

        def ChangeCipherSpec_Finished(self,session_id):
            self.SD.Create_json_object(content_type='handshake',platform='server',version=self.set_version,
                                                protocol='Change_Cipher_Spec',
                                                session_id=session_id,session_id_length=len(session_id))
            self.logger.info(str(Server.addr)+' [ Change Cipher Spec-Finished ] ')
            self.SN.send(base64.b85encode(self.SD.jsobj_dump.encode()))
            Server.c.close()
            print('Change Cipher Spec-Finished')

        def Master_key_setting(self):
            if Server.json_obj['body']['session-id'] !=None:
                self.master_key=Server().UserManagement().session_keys[Server.json_obj['body']['session-id'].encode()]
            elif Server.json_obj['body']['login-id'] !=None:
                self.master_key=Server().UserManagement().login_session_keys[Server.json_obj['body']['login-id'].encode()]
            return self.master_key

#===================================================================================================================================#
#===================================================================================================================================#

    class HANDLERS:
        def __init__(self,set_version=''):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.set_version = set_version
            self.logger=logger
            self.SN=Server().Network()
            self.SD=Server().DATA()
            self.userid,self.userpw=Server().Crypto().Decrypt_user_data(Server.json_obj['userid'],Server.json_obj['userpw'])
            self.User=Server().User(self.userid,self.userpw)
            self.verified_Userid,self.verified_Userpw,=self.User.verify_credentials()

        def Sign_Up_handler(self):
            self.verified_Userpw=self.Server().User(self.verified_Userid,self.verified_Userpw).pwd_hashing()
            if Server().SessionManager().sessions[Server.json_obj['body']['session-id'].encode()]['User addres']==Server.ip:
                Server().DBManagement().new_database_definition(self.verified_Userid,self.verified_Userpw)
                self.logger.info(str(Server.addr)+' [ User info update ]: '+self.verified_Userid)
                self.SD.Create_json_object(content_type='Sign_Up-report',platform='server',version=self.set_version,
                                            protocol='Sign_up_complete')
                self.verified_jsobj_dump=Server().Crypto().hmac_cipher(self.SD.jsobj_dump.encode())
                self.SN.send(self.verified_jsobj_dump)
                Server.c.close()

        def login_handler(self):                 
            for DB_id,DB_val in Server().database.items():
                if DB_val['user_id']==self.verified_Userid:
                    #try:
                    print(DB_val['user_pw'])
                    print(self.verified_Userpw)
                    if self.ph.verify(DB_val['user_pw'],self.verified_Userpw):
                        self.login_id=Server().SessionManager().login_session_creation(DB_id)
                        Server().SessionManager().discard_session(Server.json_obj['body']['session-id'].encode())
                        Server().SessionManager().saver()
                        self.SD.Create_json_object(content_type='login-report',platform='server',version=self.set_version,
                                                    protocol='welcome! ',
                                                    login_id=self.login_id,login_id_length=len(self.login_id))
                        self.verified_jsobj_dump=Server().Crypto().hmac_cipher(self.SD.jsobj_dump.encode())
                        self.SN.send(self.verified_jsobj_dump)
                        Server.c.close()
                    #except VerifyMismatchError: Server().ERROR().error_handler('The password does not match the supplied hash')
                else: Server().ERROR().error_handler('The user could not be found. Please proceed to sign up')

        def request_handler(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.reqdata=self.decryption_aes(base64.b85decode(self.master_secret))
            self.logger.info(str(Server.addr)+' [ get request ]: '+self.reqdata.decode())
            print(self.login_sessions.keys())
            if Server.json_obj['body']['session-id'].encode() in login_sessions.keys():
                self.SD.Create_json_object(content_type='server_master_secret',platform='server',version=self.set_version,login_id=Server.client_login_id,
                                            protocol='response',master_secret=base64.b85encode(self.encryption_aes(self.reqdata)).decode())
                self.verified_jsobj_dump=self.hmac_cipher(self.SD.jsobj_dump.encode())
                self.SN.send(self.verified_jsobj_dump)
                Server.c.close()
            else:
                Server().ERROR().error_handler('Invalid login ID')

    class ERROR:

        def error_handler(self,msg,set_version=''):
            self.logger=logger
            self.SN=Server().Network()
            self.SD=Server().DATA()
            self.logger.info(str(Server.addr)+' [ unexpected error ]: '+msg)
            self.SD.Create_json_object(content_type='return_error',platform='server',version=set_version,
                                                protocol='error',
                                                server_error=' [ unexpected error ]: '+msg)
            self.SN.send(self.SD.jsobj_dump.encode())
            Server.c.close()

#===================================================================================================================================#
#===================================================================================================================================#

    class DBManagement:
        def __init__(self):
            self.logger=logger

        def new_database_definition(self,verified_UserID,verified_Userpw, group='__user__', permission_lv=1):
            self.verified_Userpw=verified_Userpw
            self.verified_UserID=verified_UserID
            self.group=group
            self.permission_lv=permission_lv
            if Server().User()._permission_checker() == True:
                self.group='__administrator__'
            self.database_creation()

        def database_creation(self):
            token=Longinus().Random_Token_generator()
            new_database = {'user_id': self.verified_UserID, 'user_pw': self.verified_Userpw, 'permission_lv': self.permission_lv, 'group': self.group}
            Server.database.update(token,new_database)
            self.logger.info(f'[ New user database created ]: {new_database}')
            return new_database

    class SessionManager:
        def __init__(self):
            self.logger=logger

        def session_creation(self, master_key, ip, internal_ip):
            session_id, session_db = self.session_generator(ip, internal_ip)
            Server.sessions[session_id]=session_db
            Server.session_keys[session_id]=master_key
            self.logger.info(f'{ip} Session assignment complete: {session_id}')
            return session_id

        def login_session_creation(self, data, ip, internal_ip ):
            login_id, login_db = self.session_generator(ip, internal_ip)
            new_login_session = {login_id: {**data, **login_db}}
            Server.login_sessions.update(new_login_session)
            Server.login_session_keys(login_id,Server.session_keys[Server.json_obj['body']['session-id']])
            self.logger.info(f'{ip} login Session assignment complete: {login_id}')
            return login_id

        def session_generator(self, ip, internal_ip):
            token = base64.b85encode(secrets.token_bytes(32)).decode()
            now = datetime.now()
            now_after = now + timedelta(days=30)
            print(now)
            print(now_after)
            token_data = {'ip': ip, 'internal_ip': internal_ip, 'timestamp': str(now), 'validity': str(now_after)}
            print(token_data)
            return token, token_data

        def discard_session(self, session_id):
            self.logger.info('Session discarded: {session_id}')
            if Server.sessions:
                del Server.sessions[session_id]
                del Server.session_keys[session_id]

        def validate_session(self):
            pass

        def saver(self):
            self.save_session_and_database()

        def loader(self):
            global login_sessions,login_session_keys,database 
            login_sessions,login_session_keys,database = self.load_session_and_database()

        def save_session_and_database(self):
            with open('user_data.set', 'wb') as f:
                pickle.dump({'login_sessions': login_sessions, 'login_session_keys': login_session_keys, 'database': database}, f)
            self.logger.info('[ save session & database]')

        def load_session_and_database(self):
            with open('user_data.set', 'rb') as f:
                session_setup = pickle.load(f)
            return session_setup['login_sessions'], session_setup['login_session_keys'], session_setup['database']

#===================================================================================================================================#
#===================================================================================================================================#

    class Crypto:
        def __init__(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            self.ph = PasswordHasher()
            self.logger=logger

        def Decrypt_user_data(self,Cypher_userid,Cypher_userpw):
            self.userid=self._decrypt_aes(base64.b85decode(Server.cypher_userid))
            self.userpw=self.v(base64.b85decode(Server.cypher_userpw))
            return self.userid,self.userpw

        def hmac_cipher(self, data: bytes):
            hmac_data = base64.b85encode(hmac.digest(self.master_key, data, blake2b))
            verified_data = data +b'.'+hmac_data
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
            if len(Server().database) != 0:
                for DB_id,DB_val in Server().database.items():
                    return DB_val['user_id']==self.verified_UserID
            else:
                return False

        def _session_credentials(self):
            self.master_key=Server().SSLConnection().Master_key_setting()
            if (self.hmac_hash==hmac.digest(self.master_key,self.jsobj.encode(),blake2b)):
                logger.info(str(Server.addr)+' [ Session Credentials Completed ]: '+str(self.session_id))
                return True
            else:
                return False

        def _permission_checker(self):
            if (Server.ip=='127.0.0.1' and self.verified_UserID=='administrator' or self.verified_UserID=='admin'):
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

        def pwd_hashing(self):
            while True:
                temp=self.ph.hash(self.verified_Userpw)
                if (self.ph.verify(temp,self.verified_Userpw) and self.ph.check_needs_rehash(temp)!=True):
                    break
            return temp
#===================================================================================================================================#
#===================================================================================================================================#

Server().run()