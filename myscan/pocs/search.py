# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : search.py
import re
import base64
import traceback
import pickle
import time
from urllib import parse
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import get_random_str, getredis, getmd5
from myscan.lib.core.data import logger
from myscan.config import scan_set

'''
搜索模式
此搜索模式可由config.py中scan_set的search_open控制
UNDO:未能实现筛选功能,比如筛选执行extensio或者响应包的mime_stated
1.搜索范围为:burpsuite过来的数据和调用myscan的request的数据的响应包数据 (dictdata .response )
2.如果新增规则，目前仅支持在tests变量添加搜索字符串
3.contains为正则搜索bytes类型字符串，此规则关键在于写好正则表达式, 当使用search模式时候，当匹配到字符串时候，
如果contains包含()会输出()，不包含()则输出匹配到的字符串
4.search_mode 支持re的findall 和search 
5.根据host去搜索结果重
'''

tests = [
    # {"vulmsg": "email泄漏", "search_mode": "findall",
    #  "contains": b"\b[0-9a-zA-Z_\-\.]{1,19}[@]([0-9a-z]{2,13}\.)+[\w]{2,10}\b", "level": 1},
    # {"vulmsg": "身份证号码泄露", "search_mode": "findall",
    #  "contains": b"([1-9]\d{5}[12]9\d{2}(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])\d{3}[0-9xX])", "level": 0},
    # {"vulmsg": "内网IP泄漏", "search_mode": "findall",
    #  "contains": b"\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.16\.\d{1,3}\.\d{1,3}\b|\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    #  "level": 0},
    {"vulmsg": "directory_browser", "search_mode": "search",
     "contains": b"directory listing for|<title>directory|<head><title>index of|<table summary=\"directory listing\"|last modified</a>",
     "level": 1,
     "max":15
     },
    {"vulmsg": "iis_path_leak", "search_mode": "search",
     "contains": b"<th>\xe7\x89\xa9\xe7\x90\x86\xe8\xb7\xaf\xe5\xbe\x84</th><td>(&nbsp;)*?[A-Z]",
     "level": 1
     },
    {"vulmsg": "thinkphp_path_leak", "search_mode": "search",
     "contains": b"#\d?\s.*?\.php\(\d?\).*?<br />",
     "level": 1
     },

]


class searchmsg():
    def __init__(self, data):
        self.data = data
        self.datatype = 1 if isinstance(data, dict) else 0  # 1: data from burpdata 0: data from request's response
        self.url = self.geturl()
        self.rawrequest = self.getrequestraw()
        self.rawresponse = self.getresponseraw()

    def verify(self):
        for info in tests:
            self.max_out = info.get("max") if info.get("max") else scan_set.get("search_maxout")
            if not self.output(info.get("vulmsg")):  # 限定一下输出数目
                continue
            if self.checktest(info):
                try:
                    res = None
                    parse = ""
                    if info.get("search_mode") == "search":
                        res = re.search(info.get("contains"), self.rawresponse, re.I | re.S)
                    if info.get("search_mode") == "findall":
                        res = re.findall(info.get("contains"), self.rawresponse, re.I | re.S)
                    if res!=None:
                        if info.get("search_mode") == "search":
                            if res.groups():
                                parse = res.groups()
                            else:
                                parse = res.group()
                        if info.get("search_mode") == "findall":
                            parse = str(res)

                        self.saveresult({
                            "name": "sensitive_msg_leak",
                            "url": self.url,
                            "level": info.get("level"),  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": info.get("vulmsg"),
                                "search": "mode:{search_mode} contains:{contains}".format(**info),
                                "parse": parse,
                                "request": self.rawrequest[:300]+b"..." if len(self.rawrequest)>300 else self.rawrequest,
                                "response": self.rawresponse[:300]+b"..." if len(self.rawresponse)>300 else self.rawresponse
                            }
                        },info)
                except Exception as ex:
                    # print(traceback.print_exc())
                    logger.warning("run search poc get error:" + str(ex))

    def geturl(self):
        if self.datatype == 1:
            return self.data.get("url").get("url")
        if self.datatype == 0:
            return self.data.url

    def getrequestraw(self):
        if self.datatype == 1:
            return base64.b64decode(self.data.get("request").get("raw"))
        if self.datatype == 0:
            res = response_parser(self.data)
            return res.getrequestraw()

    def getresponseraw(self):
        if self.datatype == 1:
            return base64.b64decode(self.data.get("response").get("raw"))
        if self.datatype == 0:
            res = response_parser(self.data)
            return res.getresponseraw()

    def checktest(self, test):
        for k in ["search_mode", "contains", "vulmsg", "level"]:
            if k not in test.keys():
                logger.warning("search test:{} no {} key".format(test, k))
                return False
        return True

    def saveresult(self,result_data,info):
        red = getredis()
        if not result_data.get("createtime", None):
            result_data["createtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        parsehash = hash(
            str(result_data.get("detail").get("parse")) + result_data.get("url") + result_data.get("name"))
        hosthash = "saerch_" + str(hash(parse.urlparse(result_data.get("url")).netloc.split(":")[0]))
        if not red.sismember(hosthash, parsehash):
            self.output(info.get("vulmsg"), insert=True)
            red.sadd(hosthash, parsehash)
            logger.critical(result_data)
            random_id = get_random_str(9)
            red.set("result_" + random_id, pickle.dumps(result_data))
            red.lpush("vuln_" + result_data["name"].replace(" ", "_"), "result_" + random_id)
            red.lpush("vuln_all", "result_" + random_id)
            red.lpush("vuln_all_write", "result_" + random_id)  # 保存结果到html,save线程取

    def output(self, msg, insert=False):
        msg = "/".join(self.geturl().split("/")[:3]) + " " + msg
        msgmd5 = getmd5(msg)[10:18]
        red = getredis()
        if insert == False:
            if not red.sismember("myscan_max_output", msgmd5):
                return True # 可以输出
            else:
                # logger.debug("sql boolen moudle : {} 输出个数已达{}上限，不再测试输出".format(msg, self.verify_count))
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
        #     if self.max_out >= int(count.decode()):
        #         return True  # 可以输出
        #     else:
        #         logger.debug("{} 输出个数已达{}上限，不再测试输出".format(msg, self.max_out))
        #         return False  # 不可以继续输出
        # else:
        #     red.hincrby("myscan_max_output", msgmd5, amount=1)
