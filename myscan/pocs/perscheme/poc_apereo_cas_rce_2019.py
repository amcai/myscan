# !/usr/bin/env python3
# @Time    : 2020/12/25
# @Author  : caicai
# @File    : poc_apereo_cas_rce_2019.py

'''
被动触发
'''

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.pocs.perfolder.apereo.poc_apereo_cas_rce_2019 import POC as mypoc


class POC():
    def __init__(self, workdata):
        self.workdata = workdata
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "apereo_cas_rce"
        self.vulmsg = "detail: https://github.com/vulhub/vulhub/blob/master/apereo-cas/4.1-rce/README.zh-cn.md"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.dictdata.get("request").get("method").lower() != "post":
            return
        self.parser = dictdata_parser(self.dictdata)
        if b"&lt=LT-" in self.parser.getrequestbody():
            poc = mypoc(self.workdata)
            poc.verify()
            self.result = poc.result
