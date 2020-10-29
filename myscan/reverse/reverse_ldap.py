#!/usr/bin/env python3
# @Time    : 2020-06-09
# @Author  : caicai
# @File    : reverse_ldap.py


import socket
import threading
import struct
from myscan.config import reverse_set
import time
from myscan.lib.core.common_reverse import insert_db
import binascii
from myscan.lib.core.data import logger
from ldaptor.protocols import pureldap, pureber


def decode(query):
    info = ""
    try:
        info = binascii.a2b_hex(query[4:].encode()).decode()
    except Exception as ex:
        logger.warning("decode ldap error:{} sourquery:{}".format(ex, query))
    return info


def getldappath(buff):
    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()),
            inherit=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext())))
    # buff=b'\x30\x81\xa9\x02\x01\x02c\x81\x86\x04fAaBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\x01\x00\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass0\x00\xa0\x1b0\x19\x04\x172.16.840.1.113730.3.4.2'
    try:
        o, bytes = pureber.berDecodeObject(
            berdecoder, buff)
        return o.value.baseObject
    except pureber.BERExceptionInsufficientData as ex:
        logger.warning("get error:{}".format(ex))
        return None


def ldap_response(client, address):
    try:
        client.settimeout(30)
        buf = client.recv(512)
        if buf.hex().startswith("300c0201"):
            send_data = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
            client.send(send_data)
            total = 3  # 防止socket的recv接收数据不完整
            buf1 = b""
            while total:
                buf1 += client.recv(512)
                if len(buf1) > 16:
                    break
            if buf1:
                path = getldappath(buf1).decode(errors="ignore")
                logger.debug("client:{} send path:{}".format(address, path))
                res = {}
                res["type"] = "ldap"
                res["client"] = address[0]
                res["query"] = path
                res["info"] = decode(path)
                res["time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                logger.info("Insert to db:" + str(res))
                insert_db(res)
    except Exception as ex:
        logger.warning('Run ldap error:{} address:{}'.format(ex, address))
    finally:
        client.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ip=reverse_set.get("reverse_ldap_ip")
    ip="0.0.0.0" # 这里不用配置中的ip是因为，像腾讯云，监听IP是个内网，但是有个公网地址。
    port=int(reverse_set.get("reverse_ldap_port"))
    sock.bind((ip, port))
    sock.listen(200)
    while True:
        client, address = sock.accept()
        thread = threading.Thread(target=ldap_response, args=(client, address))
        thread.setDaemon(True)
        thread.start()

def ldap_start():
    main()
