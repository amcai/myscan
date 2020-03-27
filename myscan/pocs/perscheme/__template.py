# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : __template.py


#此脚本为编写perscheme的poc模板，编写poc时复制一份此模版为pocname即可，用户可在verify方法下添加自己代码


from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata") #python的dict数据，详情请看docs/开发指南Example dict数据示例
                                 #scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "your poc name"
        self.vulmsg="your poc detail msg"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        pass
        self.result.append({
            "name": self.name,
            "url": "http://example.com/test.php",
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
            }
        })