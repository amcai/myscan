#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : pythonpoc.py
import pickle
import time
import copy
from myscan.lib.core.data import cmd_line_options
import os
from myscan.lib.core.common import getredis, get_random_str
from myscan.lib.core.data import logger
from myscan.lib.core.register import load_file_to_module


class python_poc():
    def __init__(self, workdata):
        self.workdata = workdata
        self.red = getredis()
    def run(self):

        # for poc in self.pockeys[self.workdata.get("type")]:
        #     func = load_file_to_module(poc)
        #     self.poc = poc
        #     class_poc = func.POC(copy.deepcopy(self.workdata))
        #     logger.debug("Start python script:{}".format(poc))
        #     class_poc.verify()
        #     if class_poc.result:
        #         self.result = copy.deepcopy(class_poc.result)
        #         self.saveResult()
        #         # logger.critical(poc.result)
        #     logger.debug("Done python script:{}".format(poc))
        for poc_info in cmd_line_options.pocs_load_moudle[self.workdata.get("type")]:
            self.poc = poc_info.get("poc")
            func=poc_info.get("class")
            class_poc = func.POC(copy.deepcopy(self.workdata))
            logger.debug("Start python script:{}".format(self.poc))
            class_poc.verify()
            if class_poc.result:
                self.result = copy.deepcopy(class_poc.result)
                self.saveResult()
                # logger.critical(poc.result)
            logger.debug("Done python script:{}".format(self.poc))
    def saveResult(self):
        for result in self.result:
            if not isinstance(result, dict):
                logger.warning("Poc (python script) result error,it's a dict .")
                return
            result_data = {
                "name": result.get("name", os.path.splitext(os.path.split(self.poc)[-1])[0]),
                "url": result.get("url", self.workdata.get("dictdata").get("url").get("url")),
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

            logger.critical(result_data)
