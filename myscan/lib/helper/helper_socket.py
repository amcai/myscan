#!/usr/bin/env python3
# @Time    : 2020-02-26
# @Author  : caicai
# @File    : helper_socket.py
import socket
import ssl


def socket_send(data, address, timeout=8, recv_len=4096):
    '''
    data: bytes
    address: list (ip,port)
    '''
    res = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(address)
        sock.send(data)
        res = sock.recv(recv_len)
        sock.close()
    except Exception as ex:
        pass
        # ("socket_send get error:{}".format(ex))
    return res


def socket_send_withssl(data, address, timeout=8, recv_len=4096):
    '''
    data: bytes
    address: list (ip,port)
    '''
    res = None
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection(address) as conn:
            with context.wrap_socket(conn) as sconn:
                sconn.settimeout(timeout)
                sconn.send(data)
                res = sconn.recv(recv_len)
    except Exception as ex:
        pass
        # log("socket_send_withssl get error:{}".format(ex))
    return res
