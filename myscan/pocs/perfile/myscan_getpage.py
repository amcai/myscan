#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : myscan_getpage.py

'''
勿删除此脚本，此脚本不会有任何漏洞输出，目的是通过封装的request，GET请求文件，search模块去搜索响应包，让search模块输出漏洞。
'''
from myscan.lib.helper.request import request

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "your poc name"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        req = {
            "method": "GET",
            "url": self.url,
            "headers": self.dictdata.get("request").get("headers"),
            "timeout": 10,
            "verify": False,
            "allow_redirects": True,
        }
        r = request(**req)



