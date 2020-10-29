# !/usr/bin/env python3
# @Time    : 2020/10/7
# @Author  : caicai
# @File    : myscan_dns_zone_transfer.py

from myscan.lib.core.base import PocBase
from myscan.lib.core.common import is_ipaddr
import dns.resolver
import dns.reversename
import dns.zone
import dns.exception
import json

TIMEOUT = 15.0


def nameservers(fqdn):
    try:
        ans = dns.resolver.query(fqdn, 'NS')
        return [a.to_text() for a in ans]

    except dns.exception.DNSException:
        return []


def axfr(domain, ns):
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=TIMEOUT))
        return [z[n].to_text(n) for n in z.nodes.keys()]

    except:
        return None


def check_dns_zone_transfer(domain):
    # domain = "sxau.edu.cn"
    nservers = [n for n in nameservers(domain)]
    result = []
    for ns in nservers:
        recs = axfr(domain, ns)
        if recs is not None:
            result.append(
                {
                    "domain": domain,
                    "nameserver": ns,
                    "data": recs
                }

            )
    if result:
        return True, result
    return False, result


if __name__ == '__main__':
    res, resdata = check_dns_zone_transfer("zju.edu.cn")
    if res:
        for x in resdata:
            print(json.dumps(x, indent=3))


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "dns_zone_transfer"
        self.vulmsg = "dns域传送漏洞"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        host = self.dictdata["url"]["host"]
        if is_ipaddr(host):
            return
        domains = self.split_domain_and_check(host)
        if domains:
            for domain in domains:
                res, resdata = check_dns_zone_transfer(domain)
                if res:
                    self.result.append({
                        "name": self.name,
                        "url": self.url,
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "data": resdata
                        }
                    })

    def split_domain_and_check(self, domain):
        domains = []
        for num in range(domain.count(".")):
            res = ".".join(domain.split(".")[-(num + 1):])
            if self.can_output(res + self.name):
                self.can_output(res + self.name,True)
                domains.append(res)
        return domains
