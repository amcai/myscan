# !/usr/bin/env python3
# @Time    : 2020/9/19
# @Author  : caicai
# @File    : ipv6_patch.py

import socket
import urllib3
from myscan.lib.core.data import cmd_line_options, logger


def allowed_gai_family():
    family = socket.AF_INET
    if cmd_line_options.ipv6:
        logger.debug("Using ipv6 priority")
        family = socket.AF_UNSPEC
    return family


def ipv6_patch():
    urllib3.util.connection.allowed_gai_family = allowed_gai_family
