# !/usr/bin/env python3
# @Time    : 2020/9/19
# @Author  : caicai
# @File    : ignore_test.py
import socket
import urllib3
import requests

USE_IPV6 = True


def allowed_gai_family():
    family = socket.AF_INET
    if USE_IPV6:
        family = socket.AF_UNSPEC
    return family


urllib3.util.connection.allowed_gai_family = allowed_gai_family

r=requests.get("http://www.qq.com/",proxies={"http":"http://127.0.0.1:8080"},allow_redirects=True)
print(r.status_code)
