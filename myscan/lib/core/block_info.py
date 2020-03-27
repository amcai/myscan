#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : block_info.py
from myscan.lib.core.common import getredis
from myscan.config import scan_set


class block_info():
    def __init__(self, host, port):
        self.red = getredis()
        self.host_port = "{}_{}".format(host, port)
        self.count_res_key = "count_res_{}".format(self.host_port)  # list
        self.block_key = "block"  # set

    def push_result_status(self, status):
        '''
        status  [0,1]
        0:状态正常
        1:状态异常
        '''
        # 查看主机是否被封算法
        # 把主机（host_port）最近两百个结果保存到redis,统计最近两百个结果timeout次数，达到80及为主机被封，不再处理。
        if not self.red.exists(self.count_res_key):
            if int(scan_set.get("block_count", 80))>200:
                for x in range(int(scan_set.get("block_count", 80))):
                    self.red.rpush(self.count_res_key, "0")
            else:
                for x in range(200):
                    self.red.rpush(self.count_res_key, "0")
        self.red.rpush(self.count_res_key, str(status))
        self.red.ltrim(self.count_res_key, 1, -1)
        r = self.red.lrange(self.count_res_key, 0, -1)
        error_nums = r.count(b"1")
        if error_nums >= int(scan_set.get("block_count", 80)):
            self.red.sadd(self.block_key, self.host_port)
            self.red.hincrby("count_all", "block_host", amount=1)
        return error_nums

    def is_block(self):
        if self.red.sismember(self.block_key, self.host_port):
            return True
        else:
            return False
