# !/usr/bin/env python3
# @Time    : 2020/9/28
# @Author  : caicai
# @File    : myscan_baseline.py
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
import re
from myscan.lib.core.base import PocBase


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "baseline"
        self.vulmsg = "基线检查，包含版本泄漏，jquery库xss，等其他"
        self.level = 0  # 0:Low  1:Medium 2:High
        self.parse = dictdata_parser(self.dictdata)

    def verify(self):
        self.server_version_leak()
        self.x_powered_by_version_leak()
    def server_version_leak(self):
        msg = "Server version leak"
        if not self.can_output(self.parse.getrootpath() + self.name + msg):  # 限定只输出一次
            return
        version=re.search(r"((\d{1,6}\.){1,}\d{1,6})", self.dictdata["response"]["headers"].get("Server", ""))
        if version:
            self.can_output(self.parse.getrootpath() + self.name + msg, True)
            self.save(self.name + "-" + msg,"Server版本号泄漏 :{}".format( self.dictdata["response"]["headers"].get("Server", "")))

    def x_powered_by_version_leak(self):
        msg = "X-Powered-By version leak"
        if not self.can_output(self.parse.getrootpath() + self.name + msg):  # 限定只输出一次
            return
        version = re.search(r"((\d{1,6}\.){1,}\d{1,6})", self.dictdata["response"]["headers"].get("X-Powered-By", ""))
        if version:
            self.can_output(self.parse.getrootpath() + self.name + msg, True)
            self.save(self.name + "-" + msg,
                      "X-Powered-By版本号泄漏 :{}".format(self.dictdata["response"]["headers"].get("X-Powered-By", "")))

    def save(self, msg,vulmsg):
        self.result.append({
            "name": msg,
            "url": self.parse.getrootpath(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": vulmsg,
                "request": self.parse.getrequestraw(),
                "response": self.parse.getresponseraw()
            }
        })
