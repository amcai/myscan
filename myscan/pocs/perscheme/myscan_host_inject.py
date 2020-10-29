#!/usr/bin/env python3
# @Time    : 2020-02-26
# @Author  : caicai
# @File    : myscan_host_inject.py

from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.helper.helper_socket import socket_send_withssl, socket_send
from myscan.lib.core.const import notAcceptedExt
from myscan.config import scan_set
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "host inject"
        self.vulmsg = "host 头注入"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        parse = dictdata_parser(self.dictdata)

        if parse.getfilepath().count("/") > int(scan_set.get("max_dir", 1)) + 2:
            return
        host = self.dictdata.get("url").get("host")
        port = self.dictdata.get("url").get("port")
        addr = (host, int(port))
        reqdata = parse.getrequestraw()
        reqdata = re.sub(b"Host: .*?\r\n", b"Host: myscan.com\r\n", reqdata,1)
        if self.dictdata.get("url").get("protocol") == "https":
            res = socket_send_withssl(reqdata, addr)
        else:
            res = socket_send(reqdata, addr)
        if res:
            success=False
            if re.search(b"Location: [^\?]*?myscan\.com.*?\r\n", res):
                self.save(reqdata,res,"跳转在headers里")
                success=True
            #搜索body部分跳转
            if not success:
                for search in ["<meta[^>]*?url[\s]*?=[\s'\"]*?([^>]*?)['\"]?>", "href[\s]*?=[\s]*?['\"](.*?)['\"]",
                               "window.open\(['\"](.*?)['\"]\)", "window.navigate\(['\"](.*?)['\"]\)"]:
                    for x in re.findall(search, res.decode("utf-8",errors="ignore"), re.I):
                        if x.strip() and "myscan" in x:
                            self.save(reqdata,res,"跳转在body里,rule:{} res:{}".format(search,x))
                            break
                return None, None
    def save(self,reqdata,res,others=""):
        self.result.append({
            "name": self.name,
            "url": self.dictdata.get("url").get("url"),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "request": reqdata,
                "response": res,
                "others":others
            }
        })