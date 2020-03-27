#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : conn.py
import sys
from myscan.lib.core.data import conn, cmd_line_options, logger
from myscan.lib.core.common import getredis,redis_conn

def set_conn():
    try:

        redis_conn()
        red=getredis()
        if not red.ping():
            error_msg = "redis ping error . will exit program"
            logger.warning(error_msg)
            sys.exit()
        else:
            logger.info("Redis ping success")
    except Exception as ex:
        error_msg =" connnect redis get error {}:please use --redis pass@host:port:db ,if pass is none ,like --redis @host:port:db".format(ex)
        logger.warning(error_msg)
        sys.exit()

    # TODO 其他连接方式


def cleandb():
    # red = redis.StrictRedis(connection_pool=conn.redis)
    red=getredis()
    if None in red.hmget("count_all", "doned", "request", "block_host","request_fail"):
        count_all = {
            "block_host": 0,  # 被封的host_port
            'doned': 0,  # 已经做过的burpdata条数
            "request": 0,  # request 次数
            "request_fail": 0,  # request fail次数
        }
        red.hmset("count_all", count_all)
    if cmd_line_options.clean:
        red.flushall()
        count_all = {
            "block_host": 0,  # 被封的host_port
            'doned': 0,  # 已经做过的burpdata条数
            "request": 0,  # request 次数
            "request_fail":0, #request fail次数
        }
        red.hmset("count_all", count_all)
