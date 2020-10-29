#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : pythonpoc.py
import pickle
import time
import copy
from myscan.lib.core.data import cmd_line_options
import os
import json
from myscan.lib.core.common import getredis, get_random_str
from myscan.lib.core.data import logger
import traceback
import os
# import psutil

class python_poc():
    def __init__(self, workdata):
        self.workdata = workdata
        self.red = getredis()

    def run(self):
        dictdata = json.loads(self.red.hget(self.workdata.get("id"), "data"))
        # count==0 则删除，防止内存过大
        current_count = self.red.hincrby(self.workdata.get("id"), "count", amount=-1)
        if current_count == 0:
            self.red.delete(self.workdata.get("id"))

        self.workdata["dictdata"] = copy.deepcopy(dictdata)
        self.poc = self.workdata.get("poc")
        func_data = cmd_line_options.pocs_load_moudle[self.workdata.get('type')].get(hash(self.poc), None)
        if func_data is None:
            logger.warning("{} poc not found,will kill this task".format(self.poc))
            return
        func = copy.deepcopy(func_data.get("class").POC)
        class_poc = func(self.workdata)
        logger.debug("Start python script:{} at {}".format(self.poc, self.workdata.get("data", "None")))
        self.red.hincrby("count_all", "active", amount=1)
        try:
            class_poc.verify()
            # process = psutil.Process(os.getpid())  # os.getpid()
            # memInfo = process.memory_info()
            # print('pid: {}'.format(os.getpid()), int(memInfo.rss / 1024 / 1014), 'mb on {}'.format(os.path.basename(self.poc)))
            if class_poc.result:
                self.result = class_poc.result
                self.saveResult()
                # logger.critical(poc.result)
            logger.debug("Done python script:{} at {}".format(self.poc, self.workdata.get("data", "None")))
        except Exception as ex:
            traceback.print_exc()
        finally:
            self.red.hincrby("count_all", "active", amount=-1)

    def saveResult(self):
        for result in self.result:
            if not isinstance(result, dict):
                logger.warning("Poc (python script) result error,it's a dict .")
                return
            url_default = ""
            if cmd_line_options.command == "webscan":
                url_default = self.workdata.get("dictdata").get("url").get("url")
            elif cmd_line_options.command == "hostscan":
                url_default = "{type}://{addr}:{port}".format(**self.workdata.get("dictdata"))
            result_data = {
                "name": result.get("name", os.path.splitext(os.path.split(self.poc)[-1])[0]),
                "url": result.get("url", url_default),
                "level": result.get("level", "-1"),
                "createtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "detail": {

                }
            }

            if result.get("detail", None) and isinstance(result.get("detail"), dict):
                result_data["detail"] = result.get("detail")
            else:
                result_data["detail"] = {"noshow": "no details"}
            random_id = get_random_str(9)
            self.red.set("result_" + random_id, pickle.dumps(result_data))
            self.red.lpush("vuln_" + result_data["name"].replace(" ", "_"), "result_" + random_id)
            self.red.lpush("vuln_all", "result_" + random_id)
            self.red.lpush("vuln_all_write", "result_" + random_id)  # 保存结果

            for k, v in result_data.get("detail").items():
                if str(k).lower().startswith("request") or str(k).lower().startswith("response"):
                    if str(v).__len__() > 1000:
                        result_data.get("detail")[k] = str(v)[:500] + " ..."
            logger.critical(result_data)
