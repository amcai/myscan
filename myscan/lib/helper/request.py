#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : request.py
import requests
import urllib3

urllib3.disable_warnings()

from myscan.lib.core.data import cmd_line_options, logger
from myscan.lib.core.common import getredis, gethostportfromurl
from myscan.lib.core.block_info import block_info
from time import sleep
from random import uniform
from myscan.pocs.search import searchmsg
from myscan.config import scan_set
import copy
from myscan.lib.core.const import key_unquote


def request(**kwargs_sour):
    return do_req(None, **kwargs_sour)


def request_session(session, **kwargs_sour):
    return do_req(session, **kwargs_sour)


def do_req(session, **kwargs_sour):
    kwargs = copy.deepcopy(kwargs_sour)
    if kwargs.get("quote", None) is not None:
        if isinstance(kwargs.get("quote"), bool):
            if not kwargs.get("quote"):
                kwargs["url"] = key_unquote + kwargs.get("url", "")
        else:
            logger.warning("requests quote args need bool")
            return
        del kwargs["quote"]
    # print("start:",kwargs)
    if not kwargs.get("verify", None):
        kwargs["verify"] = False
    if not kwargs.get("timeout", None):
        kwargs["timeout"] = 12
    if not kwargs.get("headers", None):
        kwargs["headers"] = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0"}
    elif not kwargs.get("headers").get("User-Agent", None):
        kwargs["headers"]["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0"

    if cmd_line_options.proxy:
        kwargs["proxies"] = cmd_line_options.proxy
    if cmd_line_options.timeout:
        kwargs["timeout"] = cmd_line_options.timeout
    # print("end:",kwargs)
    if kwargs.get('data', None):
        if isinstance(kwargs.get("data"), str):
            kwargs["data"] = kwargs["data"].encode("utf-8", "ignore")
    r = None
    h, p = gethostportfromurl(kwargs.get("url"))
    block = block_info(h, p)
    if block.is_block():
        return None
    # retry
    for x in range(cmd_line_options.retry + 1):
        try:
            if session is None:
                r = requests.request(**kwargs)
            else:
                r = session.request(**kwargs)
            break
        except requests.exceptions.ConnectTimeout:
            pass
            # logger.debug("request connect timeout :{}".format(kwargs["url"]))
        except requests.exceptions.ReadTimeout:
            pass
            # logger.debug("request read timeout :{}".format(kwargs["url"]))
        except Exception as ex:
            # print(kwargs)
            logger.debug("Request error url:{} error:{}".format(kwargs["url"], ex))
        sleep(uniform(0, 0.2))
    red = getredis()
    red.hincrby("count_all", "request", amount=1)
    if r != None:
        block.push_result_status(0)
        if scan_set.get("search_open", False):
            s = searchmsg(r)
            s.verify()
            # s.saveresult()
    else:
        block.push_result_status(1)
        red.hincrby("count_all", "request_fail", amount=1)
    return r
