import LServer
import re,requests,threading
S=LServer.Server()


class shell:
    def __init__(self):
        self.cmd_temp=str()
        self.value_list=list()
        self.variable_dict=dict()
        self.function_list=list()
        self.variable_list=list()
        self.cmd_list=dict()
        self.First_cmd=str()
        self.y=str()
        self.error=str()
        self.cmd_list={'server':[{'--start':S.start_server},{'--stop':None}],'set':[{'-location':'S.path'},{'-port':'S.set_port'},{'-addres':'S.set_addr'},{'--load file':S.Server_DB_loader},{'--load data':S.User_data_loader}],
                        'show':[{'-DB':'S.Server_DB'},{'-Token':'self.L.TokenDB'},{'-RSAkey':'S.pul_key'},{'-UserData':'S.userdata'}],
                        'exit':[{'--e':S.server_exit}]}
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '

    def launcher(self):
        while True:
            try:
                self.input_shell()
                if self.cmd_temp!='^C':
                    for self.y in self.cmd_temp:
                        self.uncps_command()
                        self.command_executor()
            except Exception as e:
                print(e)
                continue

    def input_shell(self):
        self.__init__()
        self.cmd_temp=input(self.text)
        self.cmd_temp=self.cmd_temp.split(' ')
        self.First_cmd=self.cmd_temp[0]
        if self.First_cmd in self.cmd_list.keys():
            self.cmd_temp.remove(self.First_cmd)
        else:
            print(' [ Command not found for ] : '+self.First_cmd)
        return self.cmd_temp

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
                        print(' '+string_val+' setting complete :',val)
        elif len(self.function_list) !=0:
            for l in range(len(self.cmd_list[self.First_cmd])):
                for f in self.function_list:
                        if f in self.cmd_list[self.First_cmd][l].keys():
                            self.cmd_list[self.First_cmd][l][f]()

shell().launcher()