# !/usr/bin/env python3
# @Time    : 2020/10/13
# @Author  : caicai
# @File    : myscan_sensitive_msg_transfer.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
import re
import copy


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sensitive_msg_transfer"
        self.vulmsg = "发现敏感信息"
        self.level = 0  # 0:Low  1:Medium 2:High
        self.parser = dictdata_parser(self.dictdata)

    def verify(self):
        # if self.dictdata.get("url").get("protocol", "") == "http":
        # msg = self.parser.getresponsebody().decode("utf-8",errors="ignore") 建议不要decode，消耗cpu
        msg = self.parser.getresponsebody()
        msg_req=self.parser.getrequestraw()
        vulns = {}
        if self.isblock():
            return
        vulns["phone found"] = self.stringIsPhone(msg+msg_req)
        vulns["idcard found"] = self.stringIsIdCard(msg+msg_req)
        vulns["natip found"] = self.stringIsAssets(msg)
        vulns["email found"] = self.stringIsEmail(msg+msg_req)
        # print(vulns)
        for k, v in copy.deepcopy(vulns).items():
            if not v:
                del vulns[k]
        if vulns:
            self.save(vulns)

    def save(self, vulns):
        data = {
            "name": self.name,
            "url": self.parser.getfilepath(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "protocol": self.dictdata.get("url").get("protocol", ""),
                "vulmsg": self.vulmsg,
                "request": self.parser.getrequestraw(),
                "response": self.parser.getresponseraw()
            }
        }
        for k, v in vulns.items():
            data["detail"][k] = str(v)
        self.result.append(data)


    def stringIsPhone(self, string):
        # iphones = re.findall(
        #     r'[^0-9](?:13[012]\d{8}[^0-9]|15[56]\d{8}[^0-9]|18[56]\d{8}[^0-9]|176\d{8}[^0-9]|145\d{8}[^0-9]|13[456789]\d{8}[^0-9]|147\d{8}[^0-9]|178\d{8}[^0-9]|15[012789]\d{8}[^0-9]|18[23478]\d{8}[^0-9]|133\d{8}[^0-9]|153\d{8}[^0-9]|189\d{8}[^0-9])'.encode(),
        #     string)
        iphones = re.findall(r'([^0-9](1[3-9]\d{9})[^0-9])'.encode(), string)
        if iphones:
            return list(set([x[1].decode() for x in iphones]))

    def stringIsAssets(self, string):
        idcards = re.findall(
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:(?:1[6-9])|(?:2\d)|(?:3[01]))\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})'.encode(),
            string)
        if idcards:
            return list(set([x.decode() for x in idcards]))

    def stringIsIdCard(self, string):
        # idcards = re.findall(
        #     r'([^0-9]([1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])|([1-9]\d{5}\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{2}[0-9Xx])[^0-9])'.encode(),
        #     string)
        idcards= re.findall(r'([^0-9]([1-8][1-7]\d{4}[1|2]\d{3}[0|1]\d{1}[1-3]\d{4}[0-9|X|x])[^0-9])'.encode(),string)

        if idcards:
            return list(set([x[1].decode() for x in idcards]))

    def stringIsEmail(self, string):
        emails = re.findall(r'([\w-]+(?:\.[\w-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?)'.encode(), string)
        if emails:
            return list(set(emails))

    def isblock(self):
        block_content_type = ["image","excel","doc"]
        ct = self.dictdata["response"]["headers"].get("Content-Type", "")
        return any([x.lower() in ct for x in block_content_type])
