#!/usr/bin/env python3
# @Time    : 2020-06-04
# @Author  : caicai
# @File    : myscan_put_upload.py


from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装
from myscan.config import scan_set
from myscan.lib.core.common import get_random_str


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "put upload"
        self.vulmsg = "can upload file"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        randompath = get_random_str(4).lower()
        randomtext = get_random_str(10)
        req = {
            "method": "PUT",
            "url": self.url + randompath,
            "data": randomtext,
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r != None and r.status_code == 201:
            req1 = {
                "method": "GET",
                "url": self.url + randompath,
                "timeout": 10,
                "allow_redirects": False,
                "verify": False,
            }
            r1 = request(**req1)
            if r1 != None and randomtext.encode() in r1.content:
                parser_ = response_parser(r1)
                self.result.append({
                    "name": self.name,
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "others":"可以PUT上传文件，且能成功访问",
                        "vulmsg": self.vulmsg,
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
                return
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": 0,  # 0:Low  1:Medium 2:High
                "detail": {
                    "others": "根据状态码显示可以PUT上传，但是访问不成功",
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
