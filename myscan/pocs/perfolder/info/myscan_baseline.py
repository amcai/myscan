# !/usr/bin/env python3
# @Time    : 2020/9/29
# @Author  : caicai
# @File    : myscan_baseline.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "baseline"
        self.vulmsg = "检查是否支持option方法"
        self.level = 0  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "OPTIONS",
            "url": self.url,
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169"
            },
            "allow_redirects": False,
            "timeout": 10,
            "verify": False,
        }
        r = request(**req)

        if r is not None:
            res = r.headers.get("Allow")
            if res:
                parse_ = response_parser(r)
                self.result.append({
                    "name": self.name+"-"+"Options open",
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "AllowMethod": res,
                        "request": parse_.getrequestraw(),
                        "response": parse_.getresponseraw()
                    }
                })
