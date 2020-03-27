#!/usr/bin/env python3
# @Time    : 2020-03-01
# @Author  : caicai
# @File    : myscan_phppath_leak.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
import copy


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "php realpath leak"
        self.vulmsg = "对于一些php网站，将正常参数替换为[]可能造成真实信息泄漏"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension")[:3] not in ["php", ""]:
            return
        parser = dictdata_parser(self.dictdata)
        # url 参数测试
        params = parser.getrequestparams_urlorcookie("url")
        if params:
            for k, v in params.items():
                params_copy = copy.deepcopy(params)
                params_copy[k + "[]"] = v
                req = parser.generaterequest({"params": params_copy})
                r = request(**req)
                self.save(r, parser)
        # body参数测试
        params_body = self.dictdata.get("request").get("params").get("params_body")
        if params_body:
            for param in params_body:
                req = parser.generaterequest({"data": parser.setrequestbody_newkey(param, "a", "[]")})
                r = request(**req)
                self.save(r, parser)

    def save(self, r, parser):
        if r:
            if "Warning" in r.text and "array given" in r.text:
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": parser.getfilepath(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })