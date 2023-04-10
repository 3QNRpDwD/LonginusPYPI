import re
import socket
import threading
import requests
import win32api
import os
import psutil
from collections import deque




class HyperTextTransferProtocol:
    def __init__(self):
        self.head = bytes()
        self.recv_datas = bytes()
        self.s = socket.socket()
        self.Thread=Thread_manager()
        self.user_thread_result_dict={}

    def start_service(self):
        self.bind_address()
        self.listen()
        #thread.get_available_threads()
        self.Thread.Create_Thread(target=self.run_http)[1].start()
        self.Thread.process_queue()


    def run_http(self):
        while True:
            c,addr=self.accept_connection()
            self.Thread.assign_user_thread((c,),addr)
            self.Thread.display_variables()
            self.Thread.Create_Thread(target=self.is_returned())[1].start()
            self.send_response()
            self.Thread.clearSessionInfo(self.find_stopped_thread())
            self.Thread.display_variables()

    def bind_address(self, address='0.0.0.0', port=80):
        req = requests.get("http://ipconfig.kr")
        ip = re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', req.text)[1]
        self.s.bind((address, port))
        print(f"[Server started on] ==> {ip}:{port}")

    def listen(self, limit=0):
        self.s.listen(limit)

    def accept_connection(self):
        global ip, col_ip, col_addr
        self.c, self.addr = self.s.accept()
        col_addr = f'\033[33m{self.addr}\033[0m'
        ip = str(self.addr).split("'")[1]
        col_ip = f'(\033[38;5;214m{ip}\033[0m)'
        print('---------------------------------------------')
        print(f"[Connected with] ==> {col_addr}")
        return self.c, self.addr

    def receive_data(self,c=None, MAX_RECV_SIZE=2048):
        self.recv_datas = b''
        while True:
            if b'\r\n\r\n' in self.recv_datas:
                break
            if c==None:
                self.recv_datas += self.c.recv(MAX_RECV_SIZE)
            self.recv_datas += c.recv(MAX_RECV_SIZE)
            if b'GET' in self.recv_datas:
                print(f'[GET request from] ==> {col_addr}')
            return self.recv_datas

    def send_response(self):
        for user,result in self.user_thread_result_dict.items():
            for user_address,soket in self.Thread.user_socket_dict.items():
                if user == user_address:
                    soket[0].send(result)
                    print(f'[Response sent to] ==> {user_address}')
                    soket[0].close()
                    print(f'[Disconnected from] ==> {user_address}')

    def find_stopped_thread(self):
        for thread_name,user_addr in self.Thread.SESSIONS.items():
            if 'stopped' in str(eval(thread_name)):
                return thread_name
            return None
            
            
    def is_returned(self):
        while True:
            for thread_name,thread in self.Thread.ACTIVATED_THREADS.items():
                for session_name,user_address in self.Thread.SESSIONS.items():
                    if thread_name == session_name:
                        if thread.result != None:
                            user_result=self.user_thread_result_dict[user_address]=thread.result
                            return user_result



class THREAD_PRESET(threading.Thread):
    def __init__(self, target, args=() , daemon=False):
        super(THREAD_PRESET, self).__init__()
        self.target = target
        self.args = args
        self.daemon= daemon
        self.result = None

    def run(self):
        try:
            self.result = self.target(*self.args)
        except TypeError:
            pass

class Thread_manager:
    def __init__(self, MM_USERS=100):
        self.ACTIVATED_THREADS={}
        self.MAXIMUM_USERS=MM_USERS
        self.USERS=[]
        self.SESSIONS={}
        self.USERS_COUNT=0
        self.THREADS_COUNT=0
        self.thread_result_dict={}
        self.thread_queue=deque([])
        self.user_socket_dict={}

    def display_variables(self):
        LIST_VARIABLES=f'''
                            'SESSIONS':{self.SESSIONS},
                            'MAXIMUM_USERS':{self.MAXIMUM_USERS},
                            'USERS':{self.USERS},
                            'USERS_COUNT':{self.USERS_COUNT},
                            'ACTIVATED_THREADS':{self.ACTIVATED_THREADS},
                            'THREADS_COUNT':{self.THREADS_COUNT}
                            'THREADS_queue':{self.thread_queue}
                            'user_socket_dict':{self.user_socket_dict}
                        '''
        print(LIST_VARIABLES)


    def Create_Thread(self, target, args=(), daemon=False):
            while True:
                new_thread_name='THREAD_{}'.format(self.THREADS_COUNT)
                if new_thread_name not in self.ACTIVATED_THREADS.keys():
                    globals()[new_thread_name] = THREAD_PRESET(target=target,args=args,daemon=daemon)
                    new_thread=globals()[new_thread_name]
                    self.ACTIVATED_THREADS[new_thread_name]=new_thread
                    self.THREADS_COUNT+=1
                    return new_thread_name,new_thread
    
    def assign_user_thread(self,soket,ret_addres):
        thread_name,thread = self.Create_Thread(target=HyperTextTransferProtocol().receive_data,args=soket)
        self.USERS.append(ret_addres)
        self.USERS_COUNT+=1
        self.SESSIONS[thread_name]=ret_addres
        self.user_socket_dict[ret_addres]=soket
        self.thread_queue.append(thread)

    def process_queue(self):
        while True:
            if len(self.thread_queue)!=0:
                thread=self.thread_queue.popleft()
                thread.start()
                
    def clearSessionInfo(self,thread_name):
        if thread_name==None:
            return None
        user=self.SESSIONS[thread_name]
        del self.SESSIONS[thread_name]
        del self.USERS[self.USERS.index(user)]
        del self.ACTIVATED_THREADS[thread_name]
        del self.user_socket_dict[user]
        self.USERS_COUNT-=1
        self.THREADS_COUNT-=1
        

    # def get_thread_limit(self):
    #     system_info = win32api.GetSystemInfo()
    #     thread_limit = system_info[6]  # dwNumberOfProcessors
    #     return thread_limit

    # def get_active_thread_count():
    #     system_info = win32api.GetSystemInfo()
    #     active_thread_count = system_info.dwNumberOfProcessors * 2  # 추정값
    #     return active_thread_count

    # def get_available_threads(self):
    #     print(self.get_thread_limit(),self.get_current_thread_count())

class PrepareHeader:
    def __init__(self, user_agent='127.0.0.1', body=None, status_code="HTTP/1.1 200 OK"):
        self.body = body
        self.string_header = status_code + '\r\n'
        self.default_header = {}
        for key, value in self.default_header.items():
            line = f'{key}:{value}'
            self.string_header += line + '\r\n'
        self.string_header += '\r\n'

HyperTextTransferProtocol().start_service()