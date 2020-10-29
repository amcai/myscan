#!/usr/bin/env python3
# @Time    : 2020-05-22
# @Author  : caicai
# @File    : myscan_webpack_leak.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "webpack source leak"
        self.vulmsg = "webpack源文件泄漏,可尝试reverse-sourcemap还原"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() not in ["js"]:
            return
        req = {
            "url": self.url + ".map",
            "method": "GET",
            "verify": False,
            "allow_redirects": False,
            "timeout": 10,
        }
        r = request(**req)
        if r != None and b"webpack:///" in r.content:
            # parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    # "request": parser_.getrequestraw(),
                    # "response": parser_.getresponseraw()
                }
            })
