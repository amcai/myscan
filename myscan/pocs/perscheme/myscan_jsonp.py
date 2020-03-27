#!/usr/bin/env python3
# @Time    : 2020-03-10
# @Author  : caicai
# @File    : myscan_jsonp.py

'''
检测原理:当发现url参数中包含callback则检测，在referer中修改为另外一个host，匹配返回包的的相识度
'''
import copy
from urllib import parse as urlparse
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import similar, get_random_str
from myscan.lib.core.const import notAcceptedExt


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "jsonp"
        self.vulmsg = "接受来自其他网站请求，可能造成敏感信息窃取"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        # 配置不当
        parser = dictdata_parser(self.dictdata)
        req_headers = self.dictdata.get("request").get("headers")
        req_headers_withpayload = copy.deepcopy(req_headers)
        params_url = parser.getrequestparams_urlorcookie("url")
        if params_url and "callback" in params_url.keys():
            findit = False
            for k, v in req_headers_withpayload.items():

                if k.lower() == "referer":
                    p = urlparse.urlparse(v)
                    port = ""
                    if ":" in p.netloc:
                        netloc_, port = p.netloc.split(":", 1)
                    else:
                        netloc_ = p.netloc
                    if netloc_.count(".") < 2:
                        newnetloc = netloc_ + ".com.cn"
                    else:
                        newnetloc = netloc_ + "." + get_random_str(3).lower() + ".".join(netloc_.split(".")[-2:])
                    v = v.replace(p.netloc, newnetloc + port, 1)
                    req_headers_withpayload[k] = v
                    findit = True
                    break
            if not findit:
                req_headers_withpayload["Referer"] = "https://www.baidusectest.com/index.php"
            req = parser.generaterequest({"headers": req_headers_withpayload})
            r = request(**req)
            if r != None:
                similar_rate = similar(r.content, parser.getresponsebody())
                if similar_rate > 0.9:
                    parser_ = response_parser(r)
                    self.result.append({
                        "name": self.name,
                        "url": self.dictdata.get("url").get("url").split("?")[0],
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "resp_similar": similar_rate,
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw(),
                        }
                    })
