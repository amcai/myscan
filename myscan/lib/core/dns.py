# !/usr/bin/env python3
# @Time    : 2020/11/5
# @Author  : caicai
# @File    : dns.py

import dns.resolver
import sys, os
import copy
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import logger, others,paths
from myscan.lib.core.common import get_random_str, getredis, getmd5, is_ipaddr


class find_dns_server():
    def __init__(self):
        self.dns_servers = []

    def test_server(self, server):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.lifetime = resolver.timeout = 5.0
        try:
            resolver.nameservers = [server]
            answers = resolver.query('public-dns-a.baidu.com')  # an existed domain
            if answers[0].address != '180.76.76.76':
                raise Exception('Incorrect DNS response')
            try:
                resolver.query('test.bad.dns.lijiejie.com')  # non-existed domain

                logger.debug('[+] Bad DNS Server found %s' % server)
            except Exception as e:
                self.dns_servers.append(server)
            logger.debug('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(self.dns_servers)))
        except Exception as e:
            logger.debug('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(self.dns_servers)))

    def find_dnsservers(self):
        logger.debug('[+] Validate DNS servers')
        # for server in open('dict/dns_servers.txt').readlines():
        dns_ips = []
        for server in open(os.path.join(paths.MYSCAN_DATA_PATH, "common", "dns_servers.txt")
                           ).readlines():
            server = server.strip()
            if server and not server.startswith('#'):
                dns_ips.append(server)
        mythread(self.test_server, dns_ips, 5)
        return self.dns_servers


class find_domain_ip():
    def __init__(self, domain):
        self.domain = domain
        self.msg = set()

    def find_ip(self):
        if is_ipaddr(self.domain):
            return self.domain
        red = getredis()
        key = getmd5("domain_to_ip_" + self.domain)
        res = red.get(key)
        if res:
            return res.decode()
        mythread(self.query, copy.deepcopy(others.dns_servers), 6)
        data = ",".join(list(self.msg))
        red.set(key, data)
        return data

    def query(self, ns):
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.lifetime = 4
            resolver.timeout = 10.0
            resolver.nameservers = [ns]
            answers = resolver.query(self.domain)
            if answers:
                for answer in answers:
                    self.msg.add(answer.address)
            answers = resolver.query(self.domain, 'cname')
            if answers:
                self.msg.add(answers[0].target.to_unicode().rstrip('.'))
        except:
            pass


def is_wildcard_dns(domain, istopdomain=False, level=1):
    '''
    domain: like baidu.com or www.baidu.com
    topdomain: True--> domain is baidu.com,False--> domain is www.baidu.com

    return :
    True:
    False:
    None: error
    '''
    if not istopdomain:
        domain = ".".join(domain.split(".")[1:])
        if domain == "":
            return None  #
    red = getredis()
    key = getmd5(domain)
    if red.sismember("dns_wildcard_true", key):
        return True
    if red.sismember("dns_wildcard_false", key):
        return False
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = others.dns_servers
        answers = r.query('myscan-not-%s-test.%s' % (get_random_str(4).lower(), domain))
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            wildcard_test('any-sub-to.%s' % domain, istopdomain, 2)
        elif level == 2:
            red.sadd("dns_wildcard_true", key)
            return True
    except Exception as e:
        red.sadd("dns_wildcard_false", key)
        return False


def is_cdn_domain(domain):
    '''
    return True ,False
    '''
    red = getredis()
    key = getmd5(domain)
    if red.sismember("domain_cdn_true", key):
        return True
    if red.sismember("domain_cdn_false", key):
        return False
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = others.dns_servers
        answers = r.query('myscan-not-%s-test.%s' % (get_random_str(4).lower(), domain))
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            wildcard_test('any-sub-to.%s' % domain, istopdomain, 2)
        elif level == 2:
            red.sadd("dns_wildcard_true", key)
            return True
    except Exception as e:
        red.sadd("dns_wildcard_false", key)
        return False


if __name__ == '__main__':
    pass
