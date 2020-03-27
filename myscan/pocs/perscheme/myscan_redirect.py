#!/usr/bin/env python3
# @Time    : 2020-02-24
# @Author  : caicai
# @File    : myscan_redirect.py
'''
重定向插件
检测原理:跳转存在于
1.响应体headers的Location字段
2.响应体的body部分js中window.location.href,或meta标签http-equiv属性，等跳转
'''
import re
from urllib import parse as urlparse
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_str
from myscan.lib.core.const import notAcceptedExt,URL_ARGS


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "url redirect"
        self.vulmsg = "任意url跳转，导致目标网站跳转其他恶意页面"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        parser = dictdata_parser(self.dictdata)

        # 以下为fuzz带.的参数值,但是可能收集的跳转正则不全
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        if params:
            for param in params:
                value = urlparse.unquote(param.get("value"))
                if ("." in value and not value.replace(".", "").isdigit()) or self.isneedtest(param):  # 防止1.00这种全带数字的
                    # payloads, random_str = self.genpayload("{protocol}://{host}".format(**self.dictdata.get("url")), 6)
                    payloads, random_str = self.genpayload(value, 6)
                    payloads += list(
                        map(lambda x: x.replace(self.dictdata.get("url").get("protocol") + "://", "", 1), payloads))
                    for payload in set(payloads):
                        req = parser.getreqfromparam(param, "w", payload)
                        r = request(**req)
                        if r != None:
                            if self.findheadersredirect(r, random_str):
                                self.save(r, param.get("name"), payload, "跳转在headers里")
                                break
                            res, reg_str = self.findbodyredirect(r.text, random_str)
                            if res:
                                self.save(r, param.get('name'), payload,
                                          "跳转在body里，rule:{} result:{}".format(reg_str, res))
                                break

    def genpayload(self, value, length=3):
        value = urlparse.unquote(value).strip()
        if re.search("^http[s]?://", value):
            p = urlparse.urlparse(value)
            port = ""
            if ":" in p.netloc:
                netloc_, port = p.netloc.split(":", 1)
                port = ":" + port
            else:
                netloc_ = p.netloc
            random_str = get_random_str(length).lower()
            if netloc_.count(".") < 2:
                newnetloc = netloc_ + ".{}com.cn".format(random_str)
            else:
                newnetloc = netloc_ + "." + random_str + ".".join(netloc_.split(".")[-2:])
            newvalue = []
            newvalue.append("{}://{}#@{}{}".format(p.scheme, newnetloc, p.netloc, p.path))
            newvalue.append("{}://{}{}".format(p.scheme, newnetloc, port))
            return newvalue, random_str
        else:
            # return ["myscantest." + value + "." + get_random_str(length).lower()], "myscantest"
            return ["myscantest." + value,
                    "http://myscantest." + value,
                    "http://myscantest.{}.#{}".format(value, self.dictdata.get("url").get("host"))], \
                   "myscantest"

    def findbodyredirect(self, text, randomstr):
        for search in ["<meta[^>]*?url[\s]*?=[\s'\"]*?([^>]*?)['\"]?>", "href[\s]*?=[\s]*?['\"](.*?)['\"]",
                       "window.open\(['\"](.*?)['\"]\)", "window.navigate\(['\"](.*?)['\"]\)"]:
            for x in re.findall(search, text, re.I):
                if x.strip() and randomstr in x.split("?", 1)[0]:  # 确保在url头，不在参数里
                    return x, search
        return None, None

    def findheadersredirect(self, r, randomstr):
        text = ""
        for k, v in r.headers.items():
            if "location" in k.lower():
                text = v.strip()
        if randomstr in text.split("?")[0]:
            return True
        return False

    def isneedtest(self, param):
        name = param.get("name", "")
        if name is not "":
            for key in URL_ARGS:
                if name.lower() in key.lower():
                    return True

    def save(self, r, paramkey, paramvalue, others):
        parse_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parse_.geturl().split("?")[0],
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "paramkey": paramkey,
                "paramvalue": paramvalue,
                "others": others,
                "request": parse_.getrequestraw(),
                "response": parse_.getresponseraw()
            }
        })
