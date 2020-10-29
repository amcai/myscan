#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : languages.py
from myscan.lib.core.data import cmd_line_options, paths, logger
from myscan.lib.core.register import load_file_to_module
import copy
import traceback


class plugin():
    def __init__(self, dictdata):
        self.dictdata = dictdata
        self.run()

    def run(self):
        for plugin in cmd_line_options.open_lugins:
            try:
                c = load_file_to_module(plugin)
                class_plugin = c.plugin(copy.deepcopy(self.dictdata))
                logger.debug("Start languages script:{}".format(plugin))
                class_plugin.run()
                logger.debug("Done languages script:{}".format(plugin))
            except Exception as ex:
                traceback.print_exc()
                logger.warning("run languages script:{} error:{}".format(plugin, ex))
