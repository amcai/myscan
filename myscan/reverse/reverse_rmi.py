#!/usr/bin/env python3
# @Time    : 2020-02-25
# @Author  : caicai
# @File    : reverse_rmi.py

import socket
import threading
import struct
import time
import binascii
from myscan.lib.core.data import logger
from myscan.config import reverse_set
from myscan.lib.core.common_reverse import insert_db


def decode_rmi(query):
    info = ""
    try:
        info = binascii.a2b_hex(query[4:].encode()).decode()
    except Exception as ex:
        logger.warning("decode rmi error:{} sourquery:{}".format(ex, query))
    return info


def rmi_response(client, address):
    try:
        client.settimeout(30)
        buf = client.recv(1024)
        if b"\x4a\x52\x4d\x49" in buf:
            send_data = b"\x4e"
            send_data += struct.pack(">h", len(address[0]))
            send_data += address[0].encode()
            send_data += b"\x00\x00"
            send_data += struct.pack(">H", address[1])
            client.send(send_data)

            total = 3  # 防止socket的recv接收数据不完整
            buf1 = b""
            while total:
                buf1 += client.recv(512)
                if len(buf1) > 50:
                    break
            if buf1:
                path = bytearray(buf1).split(b"\xdf\x74")[-1][2:].decode(errors="ignore")
                print("client:{} send path:{}".format(address, path))
                res = {}
                res["type"] = "rmi"
                res["client"] = address[0]
                res["query"] = path
                res["info"] = decode_rmi(path)
                res["time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                logger.info("Insert to db:" + str(res))
                insert_db(res)
    except Exception as ex:
        logger.warning('Run rmi error:{} address:{}'.format(ex, address))
    finally:
        client.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ip=reverse_set.get("reverse_rmi_ip")
    ip="0.0.0.0" # 这里不用配置中的ip是因为，像腾讯云，监听IP是个内网，但是有个公网地址。
    ip_port = (ip, int(reverse_set.get("reverse_rmi_port")))
    sock.bind(ip_port)
    sock.listen(200)
    logger.info("RMI listen: {}:{}".format(ip,int(reverse_set.get("reverse_rmi_port"))))
    while True:
        client, address = sock.accept()
        thread = threading.Thread(target=rmi_response, args=(client, address))
        thread.setDaemon(True)
        thread.start()


def rmi_start():
    main()
