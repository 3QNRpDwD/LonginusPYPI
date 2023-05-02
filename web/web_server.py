import socket
import threading
from urllib import request
from urllib import parse
import logging
import json
import datetime as dt
import pickle

class DBManager:
    def __init__(self) -> None:
        self.ServerDB={}

    def SaveDB(self):
        with open('ServerDB.DB','wb') as WDB:
            pickle.dump(self.ServerDB,WDB)
        return 'Done'
    
    def loadDB(self):
        with open('ServerDB.DB','rb') as RDB:
            self.ServerDB=pickle.load(RDB)
        print(type( self.ServerDB))
        return 'Done'

    def CreatDB(self):
        with open('ServerDB.DB','ab') as CDB:
            pickle.dump(self.ServerDB,CDB)
        return 'Done'
    
class Log:
    def __init__(self):
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def set_logger(self):
        if not self.logger.handlers:
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(self.formatter)
            self.logger.addHandler(stream_handler)
            file_handler = logging.FileHandler('server.log')
            file_handler.setFormatter(self.formatter)
            self.logger.addHandler(file_handler)

    def logging(self, msg):
        self.set_logger()
        self.logger.info(msg)

class HyperTextTransferProtocol:
    def __init__(self):
        self.head = bytes()
        self.recv_datas = bytes()
        self.s = socket.socket()
        self.Thread=Thread_manager()
        self.log=Log().logging
        self.Content_Length=''
        self.DB=DBManager()

    def start_web_server(self):
        self.bind_address()
        self.listen()
        while True:
            user_info=self.accept_connection()
            self.Thread.Create_Thread(target=self.handle_request_thread,args=user_info)[1].start()
    
    def handle_request_thread(self, client_socket, client_address):
        socket_and_address = [(client_socket,), client_address]
        thread_name, thread = self.Thread.assign_user_thread(socket_and_address)
        thread.start()
        thread.join()
        first_line = thread.result[0]
        if 'GET' in first_line:
            query=self.HandleGETRequest(thread)
        elif 'POST' in first_line:
            file_name=thread.result[1][1].split('"')[3]
            self.ImgFileUpload(thread.result[2],f'{file_name}')
            query=self.HandleImgFileRequest(self.DB.ServerDB['Img'][file_name])
        else:
            return 'This communication is not HTTP protocol'
        self.send_response(query, socket_and_address)
        self.Thread.find_stopped_thread()
        self.Thread.clearSessionInfo(thread_name, client_address)

    def bind_address(self, address='0.0.0.0', port=80):
        external_ip = request.urlopen('https://ident.me').read().decode('utf8')  
        self.s.bind((address, port))
        self.log(f"[Server started on] ==> \033[96m{external_ip}:{port}\033[0m")

    def listen(self, limit=0):
        self.s.listen(limit)

    def accept_connection(self):
        self.c, self.addr = self.s.accept()
        self.log(msg=f"[Connected with] ==> \033[32m{self.addr}\033[0m")
        return self.c, self.addr
    
    def receive(self,socket=None, addres=None, max_recv_size=1):
        received_data = b''
        header_list=list()
        while b'\r\n\r\n' not in received_data:
            if socket is None:
                received_data += self.c.recv(max_recv_size)
            received_data += socket[0].recv(max_recv_size)
            header_list=received_data.decode().split('\r\n')
        if 'POST' in header_list[0]:
            post_header=self.receive(socket,addres)[1]
            post_body=b''
            for count in range(int(self.ExtractPostBodySize(header_list)/2048)):
                post_body+=socket[0].recv(2048)
            return 'POST',post_header,post_body
        self.log(msg=f'[{parse.unquote(header_list[0])} request from] ==> \033[33m{addres}\033[0m')
        return 'GET',header_list
                    
    def send_response(self,query,socket_and_addres):
        addr = f'\033[31m{socket_and_addres[1]}\033[0m'
        socket_and_addres[0][0].send(query)
        socket_and_addres[0][0].close()
        self.log(msg=f'[Disconnected from] ==> {addr}')
        self.Thread.finished_users.append(socket_and_addres[1])

    def HandleGETRequest(self, thread):
        result = parse.unquote(thread.result[1][0]).split(' ')[1].replace('\\','/')
        try:
            Response = self.HandleTextFileRequest()
            if '?print=' in result:
                Response = self.HandleTextFileRequest(query=result.split('=')[1])
            elif '.ico' in result:
                Response=self.HandleImgFileRequest(result)
            elif '.html' in result:
                Response=self.HandleTextFileRequest(result)
            elif '.png' in result:
                Response= self.HandleImgFileRequest(f'{result}')
            elif '/upload_from' == result:
                Response= self.HandleTextFileRequest('/upload_from.html')
            return Response
        except FileNotFoundError:
            with open('resource/nofile.html','r') as arg:
                print(f'해당 resource{result}파일을 찾을수 없습니다.')
                Error_Response=arg.read().format(msg=f'해당 resource{result}파일을 찾을수 없습니다.').encode('utf-8')
                return PrepareHeader()._response_headers(Error_Response) + Error_Response

    def ExtractPostBodySize(self, header):
        content_length_header = next((header for header in header if 'Content-Length' in header), None)
        if content_length_header:
            content_length_str = ''.join(filter(str.isdigit, content_length_header))
            return int(content_length_str)
        return 0
        
    def HandleImgFileRequest(self,img_file='/a.png'):
        with open(f'resource{img_file}', 'rb') as ImgFile:
            Response_file=ImgFile.read()
            return PrepareHeader()._response_headers(Response_file) + Response_file
        
    def HandleTextFileRequest(self,flie='/Hello world.html', query='아무튼 웹 서버임'):
        with open(f'resource{flie}','r') as TextFile:
            Response_file=TextFile.read().format(msg=query)
        return PrepareHeader()._response_headers(Response_file) + Response_file.encode('utf-8')
    
    def ImgFileUpload(self,img_file,file_name):
        self.DB.loadDB()
        with open(f'resource/ImgFileUpload{file_name}', 'wb') as ImgFile:
            ImgFile.write(img_file)
            self.DB.ServerDB['Img']={file_name:f'/ImgFileUpload/{file_name}'}
            print(self.DB.ServerDB)
            self.DB.SaveDB()
            return file_name
        

class THREAD_PRESET(threading.Thread):
    def __init__(self, target, args=() , daemon=False):
        super(THREAD_PRESET, self).__init__()
        self.target = target
        self.args = args
        self.daemon= daemon
        self.result = None

    def run(self):
        self.result = self.target(*self.args)

class Thread_DataManager:
    def __init__(self) -> None:
        self.USERS=[]
        self.SESSIONS={}
        self.USERS_COUNT=0
        self.user_socket_dict={}

class Thread_manager:
    def __init__(self):
        self.ACTIVATED_THREADS={}
        self.USERS=Thread_DataManager().USERS
        self.SESSIONS=Thread_DataManager().SESSIONS
        self.USERS_COUNT=Thread_DataManager().USERS_COUNT
        self.THREADS_COUNT=0
        self.user_socket_dict={}
        self.stopped_threads={}
        self.finished_users=[]
        self.log=Log().logging

    def display_variables(self):
        LIST_VARIABLES=f'''
                            'SESSIONS':{self.SESSIONS},
                            'USERS':{self.USERS},
                            'USERS_COUNT':{self.USERS_COUNT},
                            'ACTIVATED_THREADS':{self.ACTIVATED_THREADS},
                            'THREADS_COUNT':{self.THREADS_COUNT}
                            'user_thread_result_dict':{self.user_thread_result_dict}
                            'user_socket_dict':{self.user_socket_dict}
                            'stopped_threads':{self.stopped_threads}
                            'finished_users':{self.finished_users}
                        '''
        print(LIST_VARIABLES)

    def assign_user_thread(self,socket_and_addres):
        thread_name,thread = self.Create_Thread(target=HyperTextTransferProtocol().receive,args=socket_and_addres)
        self.USERS.append(socket_and_addres[1])
        self.USERS_COUNT+=1
        self.SESSIONS[thread_name]=socket_and_addres[1]
        self.user_socket_dict[socket_and_addres[1]]=socket_and_addres[0]
        return thread_name,thread

    def Create_Thread(self, target, args=(), daemon=False):
        thread_mutex=0
        while True:
            new_thread_name='THREAD_{}_{}'.format(target.__name__,thread_mutex)
            self.THREADS_COUNT+=1
            if new_thread_name not in self.ACTIVATED_THREADS.keys():
                globals()[new_thread_name] = THREAD_PRESET(target=target,args=args,daemon=daemon)
                new_thread=globals()[new_thread_name]
                self.ACTIVATED_THREADS[new_thread_name]=new_thread
                return new_thread_name,new_thread
            else:
                thread_mutex+=1

    def clearSessionInfo(self,thread_name,user):
        thread=eval(thread_name)
        if (thread.is_alive()==False):
            del self.user_socket_dict[user]
            del self.finished_users[self.finished_users.index(user)]
            del self.USERS[self.USERS.index(user)]
            del self.SESSIONS[thread_name]
            self.USERS_COUNT-=1
        self.THREADS_COUNT-=1

    def find_stopped_thread(self):
        for activated_thread_name,thread in self.ACTIVATED_THREADS.copy().items():
            if 'stopped' in str(thread) :
                del self.ACTIVATED_THREADS[activated_thread_name]
                self.stopped_threads[activated_thread_name]=thread

class PrepareHeader:
    def __init__(self, user_agent='127.0.0.1', body=None):
        self.body = body
        self.status_code="HTTP/1.1 200 OK"
        self.string_header = self.status_code + '\r\n'
        self.default_header = {}
        for key, value in self.default_header.items():
            line = f'{key}:{value}'
            self.string_header += line + '\r\n'
        self.string_header += '\r\n'
        
    def _request_headers(self, method: str, url: str, params: dict):
        headers = {
            'Date': HttpDateTime().http_date_time,
            'User-Agent': 'longinus',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'application/json',
        }
        if params:
            url += '?' + '&'.join([f'{key}={value}' for key, value in params.items()])
        return f'{method} {url} HTTP/1.1\r\n' + \
               '\r\n'.join([f'{key}: {value}' for key, value in headers.items()]) + \
               '\r\n\r\n'

    def _response_headers(self,Content):
        headers = {
            'Date': HttpDateTime().http_date_time,
            'Server':'longinus',
            'Cache-Control': 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
            'Pragma' : 'no-cache',
            'Content-Length': len(Content)
        }
        return (f'HTTP/1.1 200 OK\r\n' + \
        '\r\n'.join([f'{key}: {value}' for key, value in headers.items()]) + \
        '\r\n\r\n').encode()

class HttpDateTime:
    def __init__(self):
        now_utc = dt.datetime.utcnow().replace(microsecond=0)
        month_dict = {
            '01': 'Jan',
            '02': 'Feb',
            '03': 'Mar',
            '04': 'Apr',
            '05': 'May',
            '06': 'Jun',
            '07': 'Jul',
            '08': 'Aug',
            '09': 'Sep',
            '10': 'Oct',
            '11': 'Nov',
            '12': 'Dec'
        }
        day_list = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        self.http_date_time = f'{day_list[now_utc.weekday()]} {now_utc.day} {month_dict[now_utc.strftime("%m")]} {now_utc.year} {now_utc.strftime("%H:%M:%S")} GMT'
        
HyperTextTransferProtocol().start_web_server()