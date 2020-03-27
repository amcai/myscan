#!/usr/bin/env python3
# @Time    : 2020-02-18
# @Author  : caicai
# @File    : myscan_power_unauth.py
import copy
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.common import similar
from myscan.lib.helper.request import request

'''
简单的越权插件
检测原理:删除请求体的token,cookie,auth字段,匹配返回体相似度
'''

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "unauth access"
        self.vulmsg = "not use cookie can access"
        self.level = 1  # 0:Low  1:Medium 2:High
        self.similar_min = 0.95  # 最小相似度

    def verify(self):
        if self.dictdata.get("url").get("extension") not in ['js', 'css', 'png', 'gif', 'svg']:
            parser = dictdata_parser(self.dictdata)
            request_headers_forpayload = self.delcookie_token()
            req = {
                "method": self.dictdata.get("request").get("method"),
                "url": parser.getfilepath(),
                "params": parser.getrequestparams_urlorcookie("url"),
                "headers": request_headers_forpayload,
                "data": parser.getrequestbody(),
                "timeout": 5,
                "verify": False,
                "allow_redirects": False,
            }
            r = request(**req)
            if r != None:
                rate = similar(r.content, parser.getresponsebody())
                if rate > self.similar_min:
                    self.result.append({
                        "name": self.name,
                        "url": parser.url.get("url"),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "similar_rate": rate,
                            "request": parser.getrequestraw(),
                            "response": parser.getresponseraw()
                        }
                    })

    def delcookie_token(self):
        request_headers = self.dictdata.get("request").get("headers")
        request_headers_forpayload = copy.deepcopy(request_headers)
        for k, v in request_headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                del request_headers_forpayload[k]
        return request_headers_forpayload
