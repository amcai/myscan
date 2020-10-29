#!/usr/bin/env python3
# @Time    : 2020-06-09
# @Author  : caicai
# @File    : base.py

'''
poc的父类，继承一些通用方法
'''
from myscan.lib.core.common import getmd5, getredis
from myscan.lib.core.data import logger

class PocBase(object):

    def can_output(self, msg, insert=False):
        '''
        msg : should url+somename
        '''

        msgmd5 = getmd5(msg)
        red = getredis()
        if insert == False:
            if not red.sismember("myscan_max_output", msgmd5):
                return True  # 可以输出
            else:
                logger.debug("{} 输出个数已达一次，不再测试输出".format(msg))
                return False  # 不可以继续输出
        else:
            # red.hincrby("myscan_max_output", msgmd5, amount=1)
            red.sadd("myscan_max_output", msgmd5)
