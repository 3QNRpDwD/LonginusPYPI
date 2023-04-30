import socket
import threading
from urllib import request
from urllib import parse
import logging
import json
import datetime as dt
import re
import os

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

    def start_web_server(self):
        self.bind_address()
        self.listen()
        while True:
            user_info=self.accept_connection()
            self.Thread.Create_Thread(target=self.handle_request_thread,args=user_info)[1].start()
    
    def handle_request_thread(self, c, addr):
        socket_and_addres=[(c,),addr]
        thread_name, thread = self.Thread.assign_user_thread(socket_and_addres)
        thread.start()
        thread.join()
        query=self.HandleGETRequest(thread)
        self.send_response(query,socket_and_addres)
        self.Thread.find_stopped_thread()
        self.Thread.clearSessionInfo(thread_name, addr)

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
    
    def receive_data(self,socket=None, addres=None, max_recv_size=2048):
        received_data = b''
        received_list=list()
        while b'\r\n\r\n' not in received_data:
            if socket is None:
                received_data += self.c.recv(max_recv_size)
            received_data += socket[0].recv(max_recv_size)
            received_list=received_data.decode().split('\r\n')
            if b'GET' in received_data:
                self.log(msg=f'[{parse.unquote(received_list[0])} request from] ==> \033[33m{addres}\033[0m')
        return received_list
                    
    def send_response(self,query,socket_and_addres):
        addr = f'\033[31m{socket_and_addres[1]}\033[0m'
        socket_and_addres[0][0].send(query)
        socket_and_addres[0][0].close()
        self.log(msg=f'[Disconnected from] ==> {addr}')
        self.Thread.finished_users.append(socket_and_addres[1])

    def HandleGETRequest(self, thread):
        result = parse.unquote(thread.result[0]).split()[1]
        try:
            Response = self.HandleTextFileRequest()
            print(Response.decode())
            if '/?print=' in result:
                Response = self.HandleTextFileRequest(query=result.split('=')[1])
            elif '.ico' in result:
                Response=self.HandleImgFileRequest(result)
            elif '.html' in result:
                Response=self.HandleTextFileRequest(flie=result)
            elif ('사진' in result):
                Response= self.HandleImgFileRequest(f'{result}.png')
            return Response
        except FileNotFoundError:
            with open('web_files\\nofile.html','r') as arg:
                print(f'해당 web_files{result}파일을 찾을수 없습니다.')
                Error_Response=arg.read().format(msg=f'해당 web_files{result}파일을 찾을수 없습니다.').encode('utf-8')
                return PrepareHeader()._response_headers(Error_Response) + Error_Response
        
    def HandleImgFileRequest(self,img_file):
        with open(f'web_files{img_file}', 'rb') as ImgFile:
            Response_file=ImgFile.read()
            return PrepareHeader()._response_headers(Response_file) + Response_file
        
    def HandleTextFileRequest(self,flie='Hello world.html', query='아무튼 웹 서버임'):
        with open(f'web_files\\{flie}','r') as TextFile:
            Response_file=TextFile.read().format(msg=query)
        return PrepareHeader()._response_headers(Response_file) + Response_file.encode('utf-8')

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
        thread_name,thread = self.Create_Thread(target=HyperTextTransferProtocol().receive_data,args=socket_and_addres)
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