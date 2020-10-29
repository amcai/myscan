# !/usr/bin/env python3
# @Time    : 2020/9/18
# @Author  : caicai
# @File    : poc_phpstudy-nginx-wrong-resolve_2020.py
'''
此处应该添加到perscheme,或者perfile
'''

from myscan.config import scan_set
from myscan.lib.helper.request import request
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.common import get_random_str, similar
from myscan.lib.core.base import PocBase


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "phpstudy-nginx-wrong-resolve"
        self.vulmsg = '''https://mp.weixin.qq.com/s/ILTuWnkzQAw0Q5-vMU3g1g"'''
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度

        if self.url.count("/") > int(scan_set.get("max_dir", 1)) + 2:
            return
        if "nginx" not in self.dictdata["response"]["headers"].get("Server", "").lower():
            return
        parse = dictdata_parser(self.dictdata)
        if not self.can_output(parse.getrootpath() + self.name):  # 限定只输出一次
            return
        random_s = get_random_str(5).lower() + ".php"

        req = {
            "method": "GET",
            "url": self.url + random_s,
            "timeout": 10,
            "verify": False,
        }

        r = request(**req)
        if r is not None and r.status_code != 200:
            path = ""
            if self.dictdata["url"]["extension"] != "php":
                path = "index.php"
            else:
                path = self.dictdata["url"]["path"][1:]
            req = {
                "method": "GET",
                "url": self.url + path,
                "timeout": 10,
                "verify": False,
            }
            r = request(**req)
            if r is not None and r.status_code == 200:
                req["url"] = self.url + path + "/.php"
                r1 = request(**req)
                if r1 is not None and r1.status_code == 200:
                    if similar(r1.content, r.content) > 0.9:
                        parse_ = response_parser(r1)
                        self.result.append({
                            "name": self.name,
                            "url": self.url,
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "request": parse_.getrequestraw(),
                                "response": parse_.getresponseraw()
                            }
                        })
                        self.can_output(parse.getrootpath() + self.name, True)
