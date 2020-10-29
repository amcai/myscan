#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : status.py
import time
from myscan.lib.core.common import getredis
from myscan.lib.core.data import logger, cmd_line_options, paths, others, conn, count
from myscan.lib.core.common_reverse import query_reverse
from myscan.config import scan_set
import threading
import traceback


def count_status():
    red = getredis()
    while True:
        try:
            time.sleep(int(scan_set.get("status_flush_time", 30)))
            burpdata_undo = red.llen("burpdata")
            if scan_set.get("random_test", False):
                # workdata = red.spop("work_data_py_set")
                unactive = red.scard("work_data_py_set")

            else:
                # red.lpush("work_data_py", pickledata)
                # workdata = red.lpop("work_data_py")

                unactive = red.llen("work_data_py")

            vuln = red.llen("vuln_all")
            data = red.hmget("count_all", "doned", "request", "block_host", "request_fail", "active")
            burpdata_doned, request, block_host, request_fail, active = list(
                map(lambda x: x.decode(), data))
            reverse_count = 0
            res, resdata = query_reverse("myscan_total")
            if res:
                reverse_count = int(resdata.get("total"))

            if cmd_line_options.command == "hostscan":
                logger.warning(
                    "do/undo/active/unactive:{}/{}/{}/{}  vuln:{}/reverse:{}".format(
                        burpdata_doned, burpdata_undo, active, unactive,
                        vuln, reverse_count), text="STATUS")
            elif cmd_line_options.command == "webscan":
                logger.warning(
                    "do/undo/active/unactive:{}/{}/{}/{} req_total/fail:{}/{} blockhost:{} vuln:{}/reverse:{}".format(
                        burpdata_doned, burpdata_undo, active, unactive, request,
                        request_fail,
                        block_host, vuln, reverse_count), text="STATUS")
        except KeyboardInterrupt as ex:
            logger.warning("Ctrl+C was pressed ,aborted program")
        except Exception as ex:
            logger.warning("Count stat moudle get error:{}".format(ex))
            traceback.print_exc()
            pass


def start_count_status():
    if cmd_line_options.verbose < 3:
        t = threading.Thread(target=count_status)
        t.daemon = True
        t.start()
