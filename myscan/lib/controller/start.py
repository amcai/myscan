#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : start.py
import random
import time
import json
import traceback
import pickle
from multiprocessing import Process
from myscan.lib.core.common import getredis
from myscan.lib.core.data import logger, cmd_line_options
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.config import scan_set
from myscan.pocs.search import searchmsg
from myscan.lib.core.pythonpoc import python_poc
from myscan.lib.core.block_info import block_info
from myscan.lib.core.plugin import plugin


def run_python():
    red = getredis()
    try:
        while True:
            try:
                workdata = red.lpop("work_data_py")
                if workdata:
                    workdata = pickle.loads(workdata)
                    logger.debug("Python poc get one data, type:" + workdata.get("type"))
                    p = python_poc(workdata)
                    p.run()
                else:
                    time.sleep(random.uniform(1, 2))
            except Exception as ex:
                traceback.print_exc()
                logger.warning("Run_python process get error:{}".format(ex))
                pass
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")
    except Exception as ex:
        traceback.print_exc()
        logger.warning("Run_python main process get error:{}".format(ex))


def process_start():
    try:
        work_process = []
        try:

            logger.info("Python Script use {} process".format(cmd_line_options.process))
            logger.info("Some process use {} threads ".format(cmd_line_options.threads))

            for x in range(cmd_line_options.process):
                work2 = Process(target=run_python)
                work_process.append(work2)
            for p in work_process:
                p.daemon = True
                p.start()
        except Exception as ex:
            err_msg = "Error occurred while starting new process ('{0}')".format(str(ex))
            logger.warning(err_msg)
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")


def start():
    logger.info("Myscan Python Moudle Listen ...")
    red = getredis()
    try:
        while True:
            data = red.lpop("burpdata")
            if data:
                red.hincrby("count_all", "doned", amount=1)
                logger.debug("Get one data from burpdata")
                dictdata = ""
                try:
                    dictdata = json.loads(data)
                except Exception as ex:
                    logger.warning("Process burpdata to json get error:" + str(ex))
                    continue
                if dictdata != "":
                    # 开启plugin
                    if cmd_line_options.plugins:
                        plugin(dictdata)
                    if "all" in cmd_line_options.disable:
                        continue
                    is_filter = dictdata.get("filter")
                    host = dictdata.get("url").get("host")
                    port = dictdata.get("url").get("port")
                    block = block_info(host, port)
                    if allow_host(host) and not block.is_block():
                        # 是否启动被动搜索模式
                        if scan_set.get("search_open", False):
                            s = searchmsg(dictdata)
                            s.verify()
                            s.saveresult()
                        data_parser = dictdata_parser(dictdata)
                        # perfile
                        if cmd_line_options.pocs_perfile:
                            if not is_filter or not data_parser.is_perfile_doned():
                                logger.debug(data_parser.getperfile().capitalize() + " is_perfile_doned res:False")
                                red.lpush("work_data_py", pickle.dumps({
                                    "data": data_parser.getperfile(),
                                    "dictdata": dictdata,
                                    "type": "perfile"
                                }))
                            else:
                                logger.debug(data_parser.getperfile().capitalize() + " is_perfile_doned res:True")
                        # perfolder
                        if cmd_line_options.pocs_perfoler:
                            if not is_filter:
                                folders = data_parser.getperfolders()
                            else:
                                folders = data_parser.is_perfolder_doned()

                            if folders != []:
                                for folder in folders:
                                    red.lpush("work_data_py", pickle.dumps({
                                        "data": folder,
                                        "dictdata": dictdata,
                                        "type": "perfolder"
                                    }))
                        # scheme
                        if cmd_line_options.pocs_perscheme:
                            if not is_filter or not data_parser.is_perscheme_doned():
                                logger.debug(data_parser.getperfile().capitalize() + " is_perscheme_doned res:False")
                                red.lpush("work_data_py", pickle.dumps({
                                    "dictdata": dictdata,  # 这里没有data字段，无关data字段了
                                    "type": "perscheme"
                                }))
                            else:
                                logger.debug(data_parser.getperfile().capitalize() + " is_perscheme_doned res:True")

                    else:
                        logger.debug("Host block:" + host)
            else:
                time.sleep(random.uniform(1, 2))
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")


def allow_host(host):
    allow_flag = 0
    if not is_in_dishost(host):
        if not cmd_line_options.host:
            allow_flag = 1
        else:
            # if host in cmd_line_options.host:
            for x in cmd_line_options.host:
                if x in host:
                    allow_flag = 1
                    break
        if allow_flag:
            return True
        return False
    else:
        return False


def is_in_dishost(host):
    for x in cmd_line_options.dishost:
        if x in host:
            return True
