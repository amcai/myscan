#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : myscan_cors.py

import copy
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import get_random_str
from myscan.lib.core.const import notAcceptedExt


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "cors"
        self.vulmsg = "寻找CORS能否利用"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        # 配置不当
        parser = dictdata_parser(self.dictdata)
        resp_headers = self.dictdata.get("response").get("headers")

        flag1 = False
        flag2 = False

        if resp_headers:
            resp_headers_lowerstr=str(resp_headers).lower()
            '''
            lowerstr like:
            {'access-control-expose-headers': 'content-range', 'server': 'nginx', 'cache-control': 'max-age=0', 'access-control-allow-origin': 'https://gia.jd.com.jd.com', 'access-control-allow-credentials': 'true', 'connection': 'keep-alive', 'vary': 'origin', 'expires': 'mon, 17 feb 2020 05:27:21 gmt', 'content-length': '0', 'date': 'mon, 17 feb 2020 05:27:21 gmt', 'content-type': 'text/html;charset=utf-8', 'accept': 'text/html'}
            '''
            if "'access-control-allow-credentials': 'true'".lower() in resp_headers_lowerstr and "'access-control-allow-origin': '*'".lower() in resp_headers_lowerstr:
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url").get("url").split("?")[0],
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request": parser.getrequestraw(),
                        "response": parser.getresponseraw(),
                    }
                })
        # 代码过滤不严
        request_headers=self.dictdata.get("request").get("headers")
        if request_headers:
            for k,v in request_headers.items():
                if "origin" in k.lower():
                    if v.count(".")<2: # 防止后续切割'.'错误
                        v+=".com.cn"
                    host=".".join(v.split(".")[-2:])
                    request_headers_forpayload=copy.deepcopy(request_headers)
                    fake_origin=(v+"."+get_random_str(3)+host).lower()
                    request_headers_forpayload[k]=fake_origin
                    req=parser.generaterequest({"headers": request_headers_forpayload})
                    r = request(**req)
                    if r!=None:
                        if r.headers:
                            for k,v in r.headers.items():
                                if k.lower()=="Access-Control-Allow-Origin".lower() and fake_origin in v.lower():
                                    parser_=response_parser(r)
                                    self.result.append({
                                        "name": self.name,
                                        "url": self.dictdata.get("url").get("url").split("?")[0],
                                        "level": self.level,  # 0:Low  1:Medium 2:High
                                        "detail": {
                                            "vulmsg": self.vulmsg,
                                            "request": parser_.getrequestraw(),
                                            "response": parser_.getresponseraw(),
                                        }
                                    })
                                    break

