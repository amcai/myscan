# !/usr/bin/env python3
# @Time    : 2020/11/4
# @Author  : caicai
# @File    : myscan_editfile_leak.py

from myscan.lib.helper.request import request
from myscan.lib.core.common import similar, get_random_str
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.const import acceptedExt
import os


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "editfile_leak"
        self.vulmsg = "maybe leak file source"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.similar_rate = 0.8

    def verify(self):
        # 添加限定条件
        if "." + self.dictdata.get("url").get("extension").lower() not in acceptedExt:
            return
        dirname = self.dictdata.get("url").get("path_folder")
        basename = os.path.basename(self.dictdata.get("url").get("path", ""))
        rand = get_random_str(6).lower()
        paths = [
            {"real": os.path.join(dirname, "." + basename + ".swp"),
             "fake": os.path.join(dirname, "." + rand + basename + ".swp")
             },
            {"real": os.path.join(dirname, basename + "~"),
             "fake": os.path.join(dirname, rand + basename + "~")
             }

        ]
        req = {
            "method": "GET",
            "url": "",
            "timeout": 10,
            "verify": False,
            "allow_redirects": False,
        }
        for path in paths:
            req["url"] = path.get("real")
            r = request(**req)
            if r is not None and r.status_code == 200 and "/html" not in r.headers.get("Content-Type",""):
                req["url"] = path.get("fake")
                r_fake = request(**req)
                if r_fake is not None and similar(r.content, r_fake.content) < 0.8:
                    self.save(r)

    def save(self, r):
        parser = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser.geturl(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "request": parser.getrequestraw(),
                "response": parser.getresponseraw(),
            }
        })
