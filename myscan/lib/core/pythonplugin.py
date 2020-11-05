# !/usr/bin/env python3
# @Time    : 2020/11/5
# @Author  : caicai
# @File    : pythonplugin.py


from myscan.lib.core.data import cmd_line_options
import json
from myscan.lib.core.common import getredis
from myscan.lib.core.data import logger
import traceback


class python_plugin():
    def __init__(self, workdata):
        self.workdata = workdata
        self.red = getredis()

    def run(self):
        dictdata = json.loads(self.red.hget(self.workdata.get("id"), "data"))
        # count==0 则删除，防止内存过大
        current_count = self.red.hincrby(self.workdata.get("id"), "count", amount=-1)
        if current_count == 0:
            logger.debug("Will delete data for id:{}".format(self.workdata.get("id")))
            self.red.delete(self.workdata.get("id"))

        # self.workdata["dictdata"] = copy.deepcopy(dictdata)
        self.poc = self.workdata.get("poc")

        func_data = cmd_line_options.allow_plugin[self.workdata.get('pochash')].get("class", None)
        if func_data is None:
            logger.warning("{} poc not found,will kill this task".format(self.poc))
            return
        func = func_data.POC
        class_poc = func(dictdata)
        logger.debug("Start python plugin script:{} ".format(self.poc))
        try:
            class_poc.verify()
            # process = psutil.Process(os.getpid())  # os.getpid()
            # memInfo = process.memory_info()
            # print('pid: {}'.format(os.getpid()), int(memInfo.rss / 1024 / 1014), 'mb on {}'.format(os.path.basename(self.poc)))

            logger.debug("Done python plugin script:{} ".format(self.poc))
        except Exception as ex:
            traceback.print_exc()
