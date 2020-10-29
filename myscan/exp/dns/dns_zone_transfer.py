import dns.resolver
import dns.reversename
import dns.zone
import dns.exception
import json
import sys
import threading
from queue import Queue

TIMEOUT = 15.0


def mythread(func, mapslist, thread_num):
    threads = []
    queue = Queue()
    for i in mapslist:
        queue.put(i)
    for x in range(0, int(thread_num)):
        threads.append(tThread(queue, func))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


class tThread(threading.Thread):
    def __init__(self, queue, func):
        threading.Thread.__init__(self)
        self.queue = queue
        self.func = func

    def run(self):

        while not self.queue.empty():
            arg = self.queue.get()
            try:
                self.func(arg)
            except Exception as e:
                print(e)
                # traceback.print_exc()


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


def checkit(domain):
    res, resdata = check_dns_zone_transfer(domain)
    if res:
        for x in resdata:
            msg = "Success: use command 'dig @{nameserver} axfr {domain}' see details".format(**x)
            print(msg)
    else:
        print("Fail: {}".format(domain))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("python file.py domainfile(line like baidu.com)")
    else:
        datas = [domain.strip() for domain in open(sys.argv[1]).readlines()]
        mythread(checkit, datas, 20)
        print("All done")
