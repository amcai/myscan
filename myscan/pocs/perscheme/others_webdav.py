#!/usr/bin/env python3
# @Time    : 2020-03-26
# @Author  : caicai
# @File    : others_webdav.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装

'''
根据headers包含Translate:、If:、Lock-Token 其中一种便认为为webdav,
'''
class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata") #python的dict数据，详情请看docs/开发指南Example dict数据示例
                                 #scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "发现webdav"
        self.vulmsg="探测到开放Webdav，可进行Webdav相关测试"
        self.level = 0  # 0:Low  1:Medium 2:High

    def verify(self):
        keys=["translate","if","lock-token"]
        parser=dictdata_parser(self.dictdata)
        for k,v in self.dictdata.get("request").get("headers").items():
            if k.lower() in keys:
                self.result.append({
                    "name": self.name,
                    "url": parser.getfilepath(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "request":parser.getrequestraw(),
                        "response":parser.getresponseraw(),
                        "vulmsg": self.vulmsg,
                    }
                })
                break