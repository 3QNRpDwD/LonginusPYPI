from LServer import *
import re,requests,threading

class shell:
    def __init__(self):
        self.S=Server()
    def server_shell(self):
        cmd_list={'server':[{'--start':self.S.start_server},{'--stop':None}],'set':[{'-location':'self.S.path'},{'-port':'self.S.set_port'},{'-addres':'self.S.set_addr'},{'--load file':self.S.Server_DB_loader},{'--load data':self.S.User_data_loader}],'show':[{'-DB':'self.S.Server_DB'},{'-Token':'self.L.TokenDB'},{'-RSAkey':'self.S.pul_key'},{'-UserData':'self.S.userdata'}],'exit':[{'--e':self.S.server_exit}]}
        self.req = requests.get("http://ipconfig.kr")
        self.req =str(re.search(r'IP Address : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.req.text)[1])
        self.text='[ Server@'+self.req+' ~]$ '
        while True:
            cmd_temp=input(self.text)
            cmd_temp=cmd_temp.split(' ')
            First_cmd=cmd_temp[0]
            if First_cmd in cmd_list.keys():
                cmd_temp.remove(First_cmd)
                for y in cmd_temp:
                    value_list=list();variable_list=list();
                    variable_dict=dict();function_list=list()
                    for v in cmd_temp.copy():
                        if ('-' in v[0] and '-' not in v[1]):
                            variable_list.append(v)
                            cmd_temp.remove(v)
                        elif ('-' in y[0] and '-' in y[1]):
                            function_list.append(v)
                            cmd_temp.remove(v)
                        elif '-' not in v[0]:
                            value_list.append(v)
                            cmd_temp.remove(v)
                    variable_dict=dict(zip(variable_list, value_list))
                    if len(variable_dict)!=0:
                        for l in range(len(cmd_list[First_cmd])):
                            for key,val in variable_dict.items():
                                if key in cmd_list[First_cmd][l].keys():
                                    string_val=cmd_list[First_cmd][l][key]
                                    exec('%s = %s' % (string_val, val))
                                    print(' '+string_val+' setting complete :',val)
                    elif len(function_list) !=0:
                        for l in range(len(cmd_list[First_cmd])):
                            for f in function_list:
                                    if f in cmd_list[First_cmd][l].keys():
                                        th =threading .Thread (target =cmd_list[First_cmd][l][f]() ).start ()
            else:
                print(' [ Command not found for ] : '+First_cmd)
shell().server_shell()