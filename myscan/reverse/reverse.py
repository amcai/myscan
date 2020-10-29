#!/usr/bin/env python3
# @Time    : 2020-02-23
# @Author  : caicai
# @File    : reverse.py
import sys

from myscan.lib.core.data import logger, cmd_line_options
from myscan.config import reverse_set
from myscan.lib.core.common import get_random_str
from myscan.reverse.reverse_http import http_start
from myscan.reverse.reverse_dns import dns_start
from myscan.reverse.reverse_rmi import rmi_start
from myscan.reverse.reverse_ldap import ldap_start
from myscan.lib.core.common_reverse import init_db
from multiprocessing import Process


def reverse_start():
    try:
        secret_key = reverse_set.get("secret_key")
        if not secret_key:
            secret_key = get_random_str(9)
        logger.info("Reverse http server: http://{}:{} secret_key: {}".format(reverse_set.get("reverse_http_ip"),
                                                                              reverse_set.get("reverse_http_port"),
                                                                              secret_key))
        logger.info("Reverse dns server: {}".format(reverse_set.get("reverse_domain")))
        logger.info("Reverse rmi server: {}:{}".format(reverse_set.get("reverse_rmi_ip"),reverse_set.get("reverse_rmi_port")))
        logger.info("Reverse ldap server: {}:{}".format(reverse_set.get("reverse_ldap_ip"),reverse_set.get("reverse_ldap_port")))

        init_db()
        try:
            p = Process(target=http_start,args=(secret_key,))
            p.daemon = True
            p.start()
            p1 = Process(target=rmi_start)
            p1.daemon = True
            p1.start()
            p2 = Process(target=ldap_start)
            p2.daemon = True
            p2.start()
            dns_start()
        except KeyboardInterrupt as ex:
            logger.warning("Ctrl+C was pressed ,aborted program")
    except Exception as ex:
        logger.warning("Start reverse get error:{}".format(ex))
        sys.exit()
