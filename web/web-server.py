import re
import socket
import threading
import requests
from collections import deque


class HyperTextTransferProtocol:
    def __init__(self):
        self.head = bytes()
        self.recv_datas = bytes()
        self.s = socket.socket()
        self.Thread=Thread_manager()
        
    def start_web_server(self):
        self.bind_address()
        self.listen()
        self.Thread.Create_Thread(self.Thread.process_queue)[1].start()
        while True:
            user_info=self.accept_connection()
            self.Thread.Create_Thread(target=self.handle_request_thread,args=user_info)[1].start()

    def remove_completed_thread(self):
        self.Thread.find_stopped_thread()
        self.Thread.clearSessionInfo()

    def handle_request_thread(self,c,addr):
        thread_name=self.Thread.assign_user_thread((c,),addr)
        self.Thread.is_returned(thread_name)
        #self.Thread.display_variables()
        self.send_response(self.Thread.user_thread_result_dict[addr],[(c,),addr])
        self.remove_completed_thread()

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
    
    def receive_data(self, sock=None, max_recv_size=2048):
        received_data = b''
        while True:
            if b'\r\n\r\n' in received_data:
                break
            if sock is None:
                received_data += self.c.recv(max_recv_size)
            received_data += sock.recv(max_recv_size)
            if b'GET' in received_data:
                print(f'[GET request from] ==> {col_addr}')
            return received_data 
                    
    def send_response(self,msg,soket):
        col_addr = f'\033[33m{soket[1]}\033[0m'
        soket[0][0].send(msg)
        print(f'[Response sent to] ==> {col_addr}')
        soket[0][0].close()
        print(f'[Disconnected from] ==> {col_addr}')
        self.Thread.finished_users.append(soket[1])

class THREAD_PRESET(threading.Thread):
    def __init__(self, target, args=() , daemon=False):
        super(THREAD_PRESET, self).__init__()
        self.target = target
        self.args = args
        self.daemon= daemon
        self.result = None

    def run(self):
        self.result = self.target(*self.args)

class Thread_manager:
    def __init__(self, MM_USERS=100):
        self.ACTIVATED_THREADS={}
        self.MAXIMUM_USERS=MM_USERS
        self.USERS=[]
        self.SESSIONS={}
        self.USERS_COUNT=0
        self.THREADS_COUNT=0
        self.thread_queue=deque([])
        self.user_socket_dict={}
        self.stopped_threads={}
        self.user_thread_result_dict={}
        self.finished_users=[]

    def display_variables(self):
        LIST_VARIABLES=f'''
                            'SESSIONS':{self.SESSIONS},
                            'MAXIMUM_USERS':{self.MAXIMUM_USERS},
                            'USERS':{self.USERS},
                            'USERS_COUNT':{self.USERS_COUNT},
                            'ACTIVATED_THREADS':{self.ACTIVATED_THREADS},
                            'THREADS_COUNT':{self.THREADS_COUNT}
                            'THREADS_queue':{self.thread_queue}
                            'user_thread_result_dict':{self.user_thread_result_dict}
                            'user_socket_dict':{self.user_socket_dict}
                            'stopped_threads':{self.stopped_threads}
                            'finished_users':{self.finished_users}
                        '''
        print(LIST_VARIABLES)

    def assign_user_thread(self,soket,ret_addres):
        thread_name,thread = self.Create_Thread(target=HyperTextTransferProtocol().receive_data,args=soket)
        self.USERS.append(ret_addres)
        self.USERS_COUNT+=1
        self.SESSIONS[thread_name]=ret_addres
        self.user_socket_dict[ret_addres]=soket
        self.thread_queue.append(thread)
        return thread_name

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
            
    def is_returned(self,thread_name):
        while True:
            for session_name, user_address in self.SESSIONS.copy().items():
                if thread_name == session_name and eval(thread_name).result is not None:
                    self.user_thread_result_dict[user_address] = eval(thread_name).result
                    return self.user_thread_result_dict

    def clearSessionInfo(self):
        for thread_name,thread in self.stopped_threads.copy().items():
            for user in self.finished_users.copy():
                print(user,self.finished_users.copy())
                if user in self.SESSIONS.copy().values() and thread_name in self.SESSIONS.copy().keys():
                    del self.SESSIONS[thread_name]
                    del self.user_socket_dict[user]
                    del self.USERS[self.USERS.index(user)]
                    del self.user_thread_result_dict[user]
                    del self.finished_users[self.finished_users.index(user)]
                    self.USERS_COUNT-=1
            thread.join()
            #thread.is_alive()
            del self.stopped_threads[thread_name]
            del self.ACTIVATED_THREADS[thread_name]
            self.THREADS_COUNT-=1
        #self.display_variables()


    def process_queue(self):
        while True:
            if len(self.thread_queue)!=0:
                thread=self.thread_queue.popleft()
                thread.start()

    def find_stopped_thread(self):
        for activated_thread_name,thread in self.ACTIVATED_THREADS.items():
            if 'stopped' in str(thread) :
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

HyperTextTransferProtocol().start_web_server()