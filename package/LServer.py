from LonginusP import *
from Cryptodome.Cipher import AES #line:32
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import subprocess,threading,sys,os,json
from socket import *
from getpass import *
from datetime import datetime
from asyncio import *
import PyQt5
from hashlib import blake2b
from argon2 import PasswordHasher
import msvcrt,re,secrets,secrets,base64,requests,struct,hmac,logging
from multiprocessing import Process

__all__=['Server']


Login_list:list=list();path:str=r'C:\Users\Eternal_Nightmare0\Desktop\Project-Longinus\package\LonginusPYPL';set_port:int=9997;set_addr:str='0.0.0.0';s=socket();
ip:str=str();Token:bytes=bytes();Token_data:dict=dict();Token_DB:dict=dict()
rdata:str='';platform:str='shell';head='';c='';addr='';Token_RSA:bytes=bytes();RSA_Key:dict=Longinus().Create_RSA_key()
address=list();sessions:list=list();prv_key:str=open(RSA_Key['private_key']).read();pul_key:str=open(RSA_Key['public_key']).read();userdata:bytes=bytes()
Server_DB:dict=dict();new_session:dict=dict()

class Server:

    L= Longinus()
    def __init__(self):
        self.set_port=set_port;self.set_addr=set_addr;self.path=path;self.cipherdata=bytes();self.decrypt_data=bytes()
        self.s=s;self.ip=ip;self.Token=Token;self.Login_list=Login_list;self.body=bytes();self.temp_db=None;self.prv_key=prv_key
        self.Token_data=Token_data;self.Token_DB=Token_DB;self.rdata=rdata;self.platform=platform;self.pul_key=pul_key
        self.head=head;self.c=c;self.addr=addr;self.Token_RSA=Token_RSA;self.address=address;self.sessions=sessions
        self.pul_key=pul_key;self.userdata=userdata;self.Server_DB=Server_DB;self.new_session=new_session;self.temp=''
        self.jsobj:str;self.client_version:str;self.rtoken:bytes;self.atoken:bytes;self.platform:str;self.internal_ip:str;self.session_keys:dict=dict()
        self.protocol:str='Preliminaries';self.content_type:str
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
            self.req = requests.get("http://ipconfig.kr")
            self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
            self.text='[ Server@'+self.req+' ~]$ '
            self.s.bind((self.set_addr,self.set_port))
            self.s.listen(0)
            self.logger.info('[ Server started at : '+self.req+' ] ')
            while True:
                try:
                    self.protocol:str='Preliminaries'
                    self.recv_head()
                    self.recv_server()
                    self.json_decompress()
                    self.protocol_execution()
                    self.recv_head()
                    self.recv_server()
                    self.json_decompress()
                    self.protocol_execution()
                except Exception as e:
                    self.error_handler(e)

    def server_hello(self):
         self.token=self.L.Random_Token_generator()
         self.Create_json_object(content_type='handshake',platform='servserclient',version='0.2.6',
                                              protocol='server_hello',random_token=self.token.decode(),random_token_length=len(self.token),
                                              public_key=self.pul_key,public_key_length=len(self.pul_key))
         self.send(self.jsobj_dump)
         self.logger.info(str(self.addr)+' [ server hello transmission complete ]: '+self.protocol)
         self.logger.info(str(self.addr)+' [ response complete ]: '+self.protocol)
         self.c.close()
         return self.jsobj_dump
         

    def Create_master_secret(self):
        self.master_key=base64.b85decode(self.master_key)
        self.master_key=self.decryptio_rsa(self.prv_key,self.master_key)
        self.Token,self.Token_data=self.L.Access_Token_generator(16,self.ip,self.internal_ip)
        self.logger.info(str(self.addr)+' [ Token Issued ]: '+str(self.Token))
        self.Token_DB[self.Token]=self.Token_data
        self.session_keys[self.Token]=self.master_key
        self.logger.info(str(self.addr)+' [ Session creation complete ]: '+self.protocol)
        self.logger.info(str(self.addr)+' [ response complete ]: '+self.protocol)
        self.logger.info(str(self.addr)+' [ Master secret creation complete ]: '+self.protocol)
        self.c.close()

    def send(self,data:str):
        self.c.send(self.merge_data(data.encode()))

    def merge_data(self,data:str):
        self.body=base64.b85encode(data)
        self.head=struct.pack("I",len(self.body))
        self.send_data=self.head+self.body
        self.logger.info(str(self.addr)+' [ Transmission data size ]: '+str(len(self.body)))
        return self.send_data

    def recv_head(self):
        #try:
        self.c,self.addr=self.s.accept();
        self.logger.info('[ Connected with ]: '+str(self.addr))
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
                self.logger.info(str(self.addr)+"  [ receiving data "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ]"+" [] Done... ] "+self.protocol)
            self.logger.info(str(self.addr)+"  [ receiving data "+str(self.addr)+"100 % ] [ Done... ] "+self.protocol)
            self.recv_datas=bytes(self.recv_datas)
        self.logger.info(str(self.addr)+' [ data received ]: '+self.protocol)
        self.logger.info(str(self.addr)+' [ Get requested ]: '+self.protocol)
        return self.recv_datas
        #except:
            #print('An unexpected error occurred')

    def json_decompress(self):
        self.recv_datas=base64.b85decode(self.recv_datas).decode()
        self.jsobj = json.loads(self.recv_datas)
        self.client_version=self.jsobj["version"]
        self.rtoken=self.jsobj['body']['random_token']
        self.atoken=self.jsobj['body']['access_token']
        self.platform=self.jsobj["platform"]
        self.internal_ip=self.jsobj["addres"]
        self.protocol=self.jsobj['body']["protocol"]
        self.content_type=self.jsobj["content-type"]
        self.UserName=self.jsobj['body']["userid"]
        self.Userpwrd=self.jsobj['body']['userpw']
        self.master_key=self.jsobj['body']['master_secret']
        self.logger.info(str(self.addr)+' [ variable assignment done ]: '+self.protocol)
        return

    def protocol_execution(self):
        if (self.content_type=='handshake' and self.protocol=='client_hello'):
            self.server_hello()
        elif (self.content_type=='handshake' and self.protocol=='client_key_exchange'):
            self.Create_master_secret()
        else:
            self.error_handler()

    def error_handler(self,msg="None"):
        self.logger.info(str(self.addr)+' [ unexpected error ]: '+str(msg))
        self.Create_json_object(content_type='return_error',platform='server',version='0.2.6',
                                            protocol='error',
                                            server_error=' [ unexpected error ]: '+str(msg))
        self.send(self.jsobj_dump)
        self.logger.info(str(self.addr)+' [ response complete ]: '+self.protocol)
        self.c.close()

    def Create_json_object(self,content_type=None,platform=None,version=None,
                                        protocol=None,random_token=None,random_token_length=None,
                                        public_key=None,public_key_length=None,server_error=None,
                                        access_token=None,access_token_length=None):
        self.jsobj={
            'content-type':content_type, 
            'platform':platform,
            'version':version,
            'body':{'protocol':protocol,
                        'random_token':random_token,
                        'random_token_length':random_token_length,
                        'access_token':access_token,
                        'access_token_length':access_token_length,
                        'public-key':public_key,
                        'public-key_length':public_key_length,
                        'server_error':server_error
                        }
         }
        self.jsobj_dump= json.dumps(self.jsobj,indent=2)
        return self.jsobj_dump

    def session_classifier(self):
        userid=self.uid
        if (userid=='Guest' or userid=='guest' or userid=='__Guest__' or userid=='__guest__'):
             self.guest_session_creator()
        elif (self.ip=='127.0.0.1'):
            self.admin_session_creator()
        else:
            self.session_creator()
        return userid

    def admin_session_creator(self):
        self.new_session={self.Token:{'user_id':self.uid,'user_pw':self.upw,'permission_lv':0,'class':'__administrator__'}}
        self.new_session[self.Token].update(self.Token_data)
        self.sessions.append(self.new_session)
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.protocol)
        return self.new_session

    def session_creator(self):
        self.new_session={self.Token:{'user_id':self.uid,'user_pw':self.upw,'permission_lv':1,'class':'__user__'}}
        self.new_session[self.Token].update(self.Token_data)
        self.sessions.append(self.new_session)
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.protocol)
        return self.new_session

    def guest_session_creator(self):
        self.new_session={self.Token:{'user_id':self.uid+str(os.urandom(8)),'user_pw':str(os.urandom(16)),'permission_lv':1,'class':'__guest__'}}
        self.new_session[self.Token].update(self.Token_data)
        self.sessions.append(self.new_session)
        self.logger.info(str(self.addr)+' [ Session assignment complete ]: '+self.protocol)
        return self.new_session

    # def recv_keys(self):
    #     while True:
    #         self.recv_datas=bytes()
    #         if self.head<2048:
    #             self.recv_datas=self.c.recv(self.head)
    #             self.recv_datas=base64.b64decode(self.recv_datas)
    #         elif self.head>=2048:
    #             self.recv_datas=bytearray()
    #             for i in range(int(self.head/2048)):
    #                 self.recv_datas.append(self.c.recv(2048))
    #                 print("  [ Downloading "+str(self.addr)+" : "+str(2048*i/self.head*100)+" % ] "+" [] Done... ] ")
    #             print("  [ Downloading "+str(self.addr)+"100 % ] [ Done... ]",'\n')
    #             self.recv_datas=base64.b64decode(bytes(self.recv_datas))
    #         print("  [ Received | Key ] ")
    #         return self.recv_datas

    def SignUp(self):
        self.UserID=self.uid
        self.Userpwrd=self.upw
        if (" " not in self.UserID and "\r\n" not in self.UserID and "\n" not in self.UserID and "\t" not in self.UserID and re.search('[`~!@#$%^&*(),<.>/?]+', self.UserID) is None):
            if (len( self.Userpwrd) > 8 and re.search('[0-9]+', self.Userpwrd) is not None and re.search('[a-zA-Z]+', self.Userpwrd) is not None and re.search('[`~!@#$%^&*(),<.>/?]+', self.Userpwrd) is not None and " " not in self.Userpwrd):
                self.Token_DB.update(self.temp_db)
                self.Token_data['SignUp']=True
                self.basepw=base64.b85encode(self.Userpwrd.encode())
                self.result=bytearray()
                for i in range(len(self.basepw)):
                    self.result.append(self.basepw[i]^self.Token[i%len(self.Token)])
                self.result=bytes(self.result)
                self.Userpwrd=self.L.pwd_hashing(bytes(self.result))
                self.upw=self.Userpwrd
                self.SignUp_data=[{'userid':self.UserID},{'userpw':self.Userpwrd}]
                self.logger.info(str(self.addr)+' [ User information update ]: '+self.UserID)
                return self.SignUp_data
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
                    self.logger.info(str(self.addr)+' [ user login ]: '+self.UserName)
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
        self.logger.info(str(self.addr)+' [ token deleted ]: '+self.Token)
        del self.Token_DB[self.Token]
        return 'done'

    def hmac_cipher(self,data:bytes):
        self.hmac_data=hmac.digest(self.master_key,data,blake2b)
        self.verified_data=data+self.hmac_data
        self.logger.info(str(self.addr)+' [ hmac applied ]: '+self.protocol)
        return self.verified_data

    def decryptio_rsa(self,set_prv_key:bytes,encrypt_data:bytes):
        private_key = RSA.import_key(set_prv_key)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        self.decrypt_data=base64.b85decode(cipher_rsa.decrypt(encrypt_data))
        self.logger.info(str(self.addr)+' [ key decryption complete ]: '+self.protocol)
        return self.decrypt_data

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
        self.logger.info(str(self.addr)+' [ data decryption complete ]: '+self.protocol)
        return data

    def Server_DB_checker(self):
        #try:
            with open(self.path+'\\SessionsDB.DB','r') as f:
                self.logger.info(str(self.addr)+' [ Checking the database ]: '+self.protocol)
                self.filedata=f.readlines()
                for line in self.filedata:
                    if ' | Sessions_data | ' in line:
                        return True
                    else:
                        return False
                self.logger.info(str(self.addr)+' [ Database check completed ]: '+self.protocol)
        #except:
            #return False

    def Server_DB_loader(self):
        if  self.Server_DB_checker() == True:
            with open(self.path+'\\SessionsDB.DB','r') as f:
                self.logger.info(str(self.addr)+' [ Loading database ]: '+self.protocol)
                self.rdata=f.readlines()
                self.User_data_loader()
                self.logger.info(str(self.addr)+' [ database load ]: '+self.protocol)

            return self.rdata

    def User_data_loader(self):
        self.logger.info(str(self.addr)+' [ Loading user data ]: '+self.protocol)
        for line in self.rdata:
            for num in range(len(line.split(' | '))):
                a=eval(line.split(' | ')[0]);b=eval(line.split(' | ')[2])
                self.Server_DB.setdefault(a,b)
        self.logger.info(str(self.addr)+' [ Load user data ]: '+self.protocol)
        return self.Server_DB

    def updata_var(self):
        self.s=s;self.ip:str=ip;self.Token:bytes=Token;self.Login_list:list=Login_list
        self.Token_data:dict=Token_data;self.Token_DB:dict=Token_DB;self.rdata:str=rdata;self.platform:str=platform
        self.head=head;self.c=c;self.addr=addr;self.Token_RSA:bytes=Token_RSA;self.address=address;self.sessions:list=sessions
        self.pul_key:bytes=pul_key;self.userdata:bytes=userdata;self.Server_DB:dict=Server_DB;self.new_session:dict=new_session

    def saveing_all_data(self):
        self.logger.info(str(self.addr)+' [ Saving database ]: '+self.protocol)
        if  self.Server_DB_checker() == True:
            with open(self.path+'\\SessionsDB.DB','a') as f:
                f.write('\n')
                f.write(str(self.new_session)+' | Sessions_data | ')
        else:
            with open(self.path+'\\SessionsDB.DB','w') as f:
                f.write(str(self.new_session)+' | Sessions_data | ')
        self.logger.info(str(self.addr)+' [ Database save complete ]: '+self.protocol)



class administration:
    L= Longinus()
    def __init__(self):
        self.Login_list2:list=list();self.path2:str=r'';self.set_port2:int=9998;self.set_addr2:str='127.0.0.1';
        self.s2=socket();self.ip:str=str();self.Token2:bytes=bytes();self.Token_data2:dict=dict()
        self.Token_DB2:dict=dict();self.rdata2:str='';self.platform2:str='administration';self.head2='';
        self.c2='';self.addr2='';self.Token_RSA2:bytes=bytes;self.address2=list();self.sessions2:list=list();
        self.pul_key2:bytes=bytes();self.userdata2:bytes=bytes();self.Server_DB:dict=dict()
        self.new_session2:dict=dict();self.result:str=str();self.recv_datas2=bytes()
        self.cmd_list={'server':[{'--start':Server().start_server},{'--stop':None},{'--update':Server().updata_var},{'--save':Server().saveing_all_data},{'--load':Server().Server_DB_loader}],
                                'set':[{'-location':'path'},{'-port':'set_port'},{'-addres':'set_addr'},{'--save':self.save_json},{'--load':self.load_json}],
                                'show':[{'-DB':'Server_DB'},{'-Token':'self.L.TokenDB'},{'-RSAkey':'pul_key'},{'-UserDatas':'sessions'},{'--all':globals}],
                                'exit':[{'--e':sys.exit}]}
        self.cmd_temp=str();self.value_list=list();self.variable_dict=dict();self.function_list=list()
        self.variable_list=list();self.First_cmd=str();self.y=str();self.error=str()
        self.s2.bind((self.set_addr2,self.set_port2))
        self.s2.listen(1)

    def run(self):
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), '[ administration started ] ')
        while True:
            self.recv_head2()
            self.recv_command()
            self.run_shell()
            self.send_result()
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.addr2 ,'[ 200 OK ] ')

    def send_result(self):
        if type(self.result).__name__!="bytes":
            self.head=struct.pack("I",len(self.result.encode()))
            self.send_data=self.head+self.result.encode()
            self.c2.send(self.send_data)
            self.c2.close()
        else:
            self.head=struct.pack("I",len(self.result))
            self.send_data=self.head+self.result
            self.c2.send(self.send_data)
            self.c2.close()

    def recv_command(self):
        if self.head2<=2048:
            self.cmd_temp=self.c2.recv(self.head2)
            self.cmd_temp=self.cmd_temp.decode()
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.addr2 ,'[ get requested ]:',self.cmd_temp)
            return self.cmd_temp
        elif self.head2>=2048:
            self.recv_datas2=bytearray()
            for i in range(int(self.head2/2048)):
                self.recv_datas2.append(self.c2.recv(2048))
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.addr2 ,'[ get requested ]:',self.cmd_temp)
            self.recv_datas2=bytes(self.recv_datas2)
            self.cmd_temp=self.recv_datas2.decode()
            return self.cmd_temp

    def recv_head2(self):
            self.c2,self.addr2=self.s2.accept();
            self.head2=self.c2.recv(4);self.head2=int(str(struct.unpack("I",self.head2)).split(',')[0].split('(')[1])
            print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), '[ Connected with admin shell ]: ',str(self.addr2))
            self.ip=str(self.addr2).split("'")[1]
            return self.head2,self.c2,self.addr2

    def run_shell(self):
            #try:
                self.cmd_temp=self.cmd_temp.split(' ')
                self.First_cmd=self.cmd_temp[0]
                if self.First_cmd in self.cmd_list.keys():
                    if self.First_cmd=='show':
                        self.cmd_temp.remove(self.First_cmd)
                        for self.y in self.cmd_temp:
                            self.uncps_command()
                            self.command_show()
                    else:
                        self.cmd_temp.remove(self.First_cmd)
                        for self.y in self.cmd_temp:
                            self.uncps_command()
                            self.command_executor()
                else:
                    self.result=' [ Command not found for ] : '+self.First_cmd
                    return ' [ Command not found for ] : '+self.First_cmd
            #except Exception as e:
                #print(e)

    def uncps_command(self):
        for v in self.cmd_temp.copy():
            if ('-' in v[0] and '-' not in v[1]):
                self.variable_list.append(v)
                self.cmd_temp.remove(v)
            elif ('-' in v[0] and '-' in self.y[1]):
                self.function_list.append(v)
                self.cmd_temp.remove(v)
            elif '-' not in v[0]:
                self.value_list.append(v)
                self.cmd_temp.remove(v)
            self.variable_dict=dict(zip(self.variable_list, self.value_list))
        return self.variable_dict

    def command_executor(self):
        if len(self.variable_dict)!=0:
            for l in range(len(self.cmd_list[self.First_cmd])):
                for key,val in self.variable_dict.items():
                    if key in self.cmd_list[self.First_cmd][l].keys():
                        string_val=self.cmd_list[self.First_cmd][l][key]
                        exec('%s = %s' % (string_val, val))
                        self.result=' '+string_val+' setting complete :'+val
                        return ' '+string_val+' setting complete :'+val
        elif len(self.function_list) !=0:
            for l in range(len(self.cmd_list[self.First_cmd])):
                for f in self.function_list:
                        if f in self.cmd_list[self.First_cmd][l].keys():
                            self.cmd_list[self.First_cmd][l][f]()
                            self.result=' '+str(f)+' function is executed :'+str(self.cmd_list[self.First_cmd][l][f])
                            return self.result_temp

    def command_show(self):
        if len(self.variable_list)!=0:
            for l in range(len(self.cmd_list[self.First_cmd])):
                for var in self.variable_list:
                    if var in self.cmd_list[self.First_cmd][l].keys():
                        string_val=self.cmd_list[self.First_cmd][l][var]
                        print(eval(string_val))
                        self.result=eval(string_val)
                        return self.result
        elif len(self.function_list) !=0:
            for l in range(len(self.cmd_list[self.First_cmd])):
                for f in self.function_list:
                        if f in self.cmd_list[self.First_cmd][l].keys():
                            self.result_temp=self.cmd_list[self.First_cmd][l][f]()
                            self.result=' '+str(f)+' function is executed :'+str(self.result_temp)
                            return self.result_temp

    def load_json(self):
        with open('settings.json') as f:
            json_obj = json.load(f)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.addr2 ,' [ load settings ] ')
        return json_obj

    def save_json(self):
        json_obj=globals()
        with open('settings.json', 'w') as f:
            json.dump(json_obj, f, indent=2,default=str)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.addr2 ,' [ Settings saved ] ')
        return json_obj

th =threading .Thread (target =Server().start_server ).start()

