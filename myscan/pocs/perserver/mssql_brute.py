# !/usr/bin/env python3
# @Time    : 2020/7/27
# @Author  : caicai
# @File    : mssql_brute.py


from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options, logger
from myscan.lib.hostscan.common import get_data_from_file
from myscan.lib.core.threads import mythread
import os,socket,binascii


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "mssql_brute"
        self.vulmsg = "mssql weak pass"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["ms-sql-s","mssql"],  # nmap本身识别为ms-sql-s ,为了以后扩展自己识别脚本,多个mssql
            "type": "tcp"
        }
        # 自定义
        self.right_pwd = None

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        pwdfile = os.path.join("brute", "mssql_pass")
        userfile = os.path.join("brute", "mssql_user")
        pwds = [""]
        pwds += get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, pwdfile))
        users = get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, userfile))
        userpass = []
        for user in users:
            for pwd in pwds:
                userpass.append((user, pwd))
        mythread(self.crack_mssql, userpass, cmd_line_options.threads)
        if self.right_pwd is not None:
            self.result.append({
                "name": self.name,
                "url": "tcp://{}:{}".format(self.addr, self.port),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "user/pwd": "/".join(self.right_pwd)
                }
            })

    def crack_mssql(self, userpwd):
        user, pass_ = userpwd
        if self.right_pwd is None:
            logger.debug("test mssql_brute userpwd:{}".format(userpwd))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(8)
                sock.connect((self.addr, self.port))
                hh = binascii.b2a_hex(self.addr.encode()).decode()
                husername = binascii.b2a_hex(user.encode()).decode()
                lusername = len(user)
                lpassword = len(pass_)
                ladd = len(self.addr) + len(str(self.port)) + 1
                hpwd = binascii.b2a_hex(pass_.encode()).decode()
                pp = binascii.b2a_hex(str(self.port).encode()).decode()
                address = hh + '3a' + pp
                # hhost = binascii.b2a_hex(ip.encode()).decode()
                data = "0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000"
                data1 = data.replace(data[16:16 + len(address)], address)
                data2 = data1.replace(data1[78:78 + len(husername)], husername)
                data3 = data2.replace(data2[140:140 + len(hpwd)], hpwd)
                if lusername >= 16:
                    data4 = data3.replace('0X', str(hex(lusername)).replace('0x', ''))
                else:
                    data4 = data3.replace('X', str(hex(lusername)).replace('0x', ''))
                if lpassword >= 16:
                    data5 = data4.replace('0Y', str(hex(lpassword)).replace('0x', ''))
                else:
                    data5 = data4.replace('Y', str(hex(lpassword)).replace('0x', ''))
                hladd = hex(ladd).replace('0x', '')
                data6 = data5.replace('ZZ', str(hladd))
                data7 = binascii.unhexlify(data6)
                sock.send(data7)
                packet = sock.recv(1024)
                if b'master' in packet:
                    self.right_pwd = userpwd
            except Exception as e:
                pass
            finally:
                sock.close()

