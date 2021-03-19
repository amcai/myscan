# !/usr/bin/env python3
# @Time    : 2020/11/27
# @Author  : caicai
# @File    : myscan_analyze_serialize_parameter.py

'''
Thanks w13scan project
'''

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.core.const import notAcceptedExt
import base64
import binascii
from myscan.lib.core.common import is_base64
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "analyze_serialize_parameter"
        self.vulmsg = "序列化参数分析插件"
        self.level = 0  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return

        params = self.dictdata.get("request").get("params").get("params_url")
        data = self.dictdata.get("request").get("params").get("params_body")
        cookies = self.dictdata.get("request").get("params").get("cookie")

        if params:
            for param in params:
                k = param.get("name", "unkonwn name")
                v = param.get("value", "")
                if len(v) > 1024:
                    continue
                self._check(k, v)

        if data:
            for param in data:
                k = param.get("name", "unkonwn name")
                v = param.get("value", "")
                if len(v) > 1024:
                    continue
                self._check(k, v)

        if cookies:
            for param in cookies:
                k = param.get("name", "unkonwn name")
                v = param.get("value", "")
                if len(v) > 1024:
                    continue
                self._check(k, v)

    def _check(self, k, v):
        whats = None
        if isJavaObjectDeserialization(v):
            whats = "JavaObjectDeserialization"
        elif isPHPObjectDeserialization(v):
            whats = "PHPObjectDeserialization"
        elif isPythonObjectDeserialization(v):
            whats = "PythonObjectDeserialization"
        if whats:
            parser_ = dictdata_parser(self.dictdata)
            self.result.append({
                "name": self.name,
                "url": parser_.getrootpath(),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "others": "{} param's value {} is {}".format(k, v, whats),
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })


def isJavaObjectDeserialization(value):
    if len(value) < 10:
        return False
    if value[0:5].lower() == "ro0ab":
        ret = is_base64(value)
        if not ret:
            return False
        if bytes(ret).startswith(bytes.fromhex("ac ed 00 05")):
            return True
    return False


def isPHPObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    if value.startswith("O:") or value.startswith("a:"):
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', value):
            return True
    elif (value.startswith("Tz") or value.startswith("YT")) and is_base64(value):
        ret = is_base64(value)
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', ret):
            return True
    return False


def isPythonObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    ret = is_base64(value)
    if not ret:
        return False
    # pickle binary
    if value.startswith(b"g"):
        if ret.startswith(bytes.fromhex("8003")) and ret.endswith(b"."):
            return True

    # pickle text versio
    elif value.startswith("K"):
        if (ret.startswith(b"(dp1") or ret.startswith(b"(lp1")) and ret.endswith(b"."):
            return True
    return False
if __name__ == '__main__':
    import pickle
    a={"a":1}
    b=pickle.dumps(a)
    print(binascii.b2a_hex(b))
