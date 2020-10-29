# !/usr/bin/env python3
# @Time    : 2020/7/23
# @Author  : caicai
# @File    : poc_consul-rce_2020.py

'''
fofa dork:
app="Consul-HashiCorp"

docker:
docker run -it --name=consul -e CONSUL_BIND_INTERFACE=eth0 -p 8500:8500 -e 'CONSUL_LOCAL_CONFIG={"disable_remote_exec": false}' -d consul

'''

from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "consul-rce"
        self.vulmsg = "referer  rexec-rce:https://www.exploit-db.com/exploits/46073 or service-rce:https://www.exploit-db.com/exploits/46074"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "v1/agent/self",
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)

        if r != None and b"\"DisableRemoteExec\": false" in r.content:
            parser_ = response_parser(r)
            self.result.append({
                "name": "consul-rexec-rce",
                "url": req.get("url"),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
        if r != None and b"\"EnableScriptChecks\": true" in r.content and b"\"EnableRemoteScriptChecks\": true" in r.content:
            parser_ = response_parser(r)
            self.result.append({
                "name": "consul-service-rce",
                "url": req.get("url"),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })


