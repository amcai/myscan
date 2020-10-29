#!/usr/bin/env python3
# @Time    : 2020-06-08
# @Author  : caicai
# @File    : others_jackson_fastjson_error_found.py


from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.base import PocBase


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "jackson_fastjson_found"
        self.vulmsg = "可尝试反序列化payload"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if not self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            return
        parse = dictdata_parser(self.dictdata)

        if not self.can_output(parse.getrootpath() + self.name):  # 限定只输出一次
            return

        body = parse.getrequestbody()
        req = parse.generaterequest({"data": body.replace(b"}", b"",1)})
        r = request(**req)
        if r != None:
            keys = ["jackson", "fastjson","autotype"]
            for key in keys:
                if key.encode() in r.content.lower():
                    parser_ = response_parser(r)
                    self.result.append({
                        "name": self.name,
                        "url": parser_.geturl(),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw()
                        }
                    })
                    self.can_output(parse.getrootpath() + self.name,True)
                    return