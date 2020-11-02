# !/usr/bin/env python3
# @Time    : 2020/11/2
# @Author  : caicai
# @File    : poc_ueditor_cnvd-2017-20077-file-upload.py

'''
未验证
'''

from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "ueditor_cnvd-2017-20077-file-upload"
        self.vulmsg = "link : https://zhuanlan.zhihu.com/p/85265552 ,https://www.freebuf.com/vuls/181814.html"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        req = {
            "url": self.url + "ueditor/net/controller.ashx?action=catchimage&encode=utf-8",
            "method": "GET",
            "headers": {
                "Accept-Encoding": "deflate"},
            "verify": False,
            "timeout": 10,
        }
        r = request(**req)
        if r is not None and r.status_code == 200 and b"\xe6\xb2\xa1\xe6\x9c\x89\xe6\x8c\x87\xe5\xae\x9a\xe6\x8a\x93\xe5\x8f\x96\xe6\xba\x90" in r.content:
            parse = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "others": "you can exploit it by :http://localhost/ueditor/net/controller.ashx?action=catchimage&encode=utf-8",
                    "request": parse.getrequestraw(),
                    "response": parse.getresponseraw(),
                }
            })
