# !/usr/bin/env python3
# @Time    : 2020/7/15
# @Author  : caicai
# @File    : rmi_deserialization.py


from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装
from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options
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
        self.name = "rmi_deserialization"
        self.vulmsg = "enum gadget"
        self.level = 0  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["rmi"],
            "type": "tcp"
        }
        # 自定义参数

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        # 还未开发
        return
        self.result.append({
            "name": self.name,
            "url": "tcp://{}:{}".format(self.addr, self.port),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
            }
        })
