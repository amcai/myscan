#!/usr/bin/env python3
# @Time    : 2020-05-13
# @Author  : caicai
# @File    : poc_jboss_found_2020.py

'''探测jboss开放'''

# 此脚本为编写perfloder的poc模板，编写poc时复制一份此模版为pocname即可，用户可在verify方法下添加自己代码
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "jboss_found"
        self.vulmsg = "发现一些jboss攻击面,可尝试反序列化payload"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "invoker/JMXInvokerServlet",
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        if r != None and r.status_code == 200 and b"org.jboss.invocation." in r.content:
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url + "invoker/JMXInvokerServlet",
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "others": "尝试用ysoserial反序列化工具去枚举payload",
                    "response": parser_.getresponseraw()
                }
            })

        req["url"] = self.url + "jbossmq-httpil/HTTPServerILServlet"
        r1 = request(**req)
        if r1 != None and b"jboss.mq" in r1.content:
            parser_ = response_parser(r1)
            self.result.append({
                "name": self.name,
                "url": self.url + "jbossmq-httpil/HTTPServerILServlet",
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "others": "尝试用ysoserial反序列化工具去枚举payload",
                    "response": parser_.getresponseraw()
                }
            })
        req["url"] = self.url + "invoker/readonly"
        r2 = request(**req)
        if r2 != None and r2.status_code == 500 and b"EOFException" in r2.content:
            parser_ = response_parser(r2)
            self.result.append({
                "name": self.name,
                "url": self.url + "invoker/readonly",
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "others": "尝试用ysoserial反序列化工具去枚举payload",
                    "response": parser_.getresponseraw()
                }
            })
        for path in ["josso/%5C../invoker/EJBInvokerServlet/",
                     "josso/%5C../invoker/JMXInvokerServlet/",
                     "invoker/EJBInvokerServlet/"]:
            req["url"] = self.url + path
            r3 = request(**req)
            if r3 is not None and b"org.jboss.invocation.MarshalledValue" in r3.content and b"java.lang" in r.content:
                parser_ = response_parser(r3)
                self.result.append({
                    "name": self.name,
                    "url": self.url + path,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others": "尝试用ysoserial反序列化工具去枚举payload",
                        "response": parser_.getresponseraw()
                    }
                })
