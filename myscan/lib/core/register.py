#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : register.py
import os
from importlib import util
from myscan.lib.core.data import logger


def load_file_to_module(file_path):
    file_path = os.path.abspath(file_path)
    if not os.path.exists(file_path):
        logger.warning("load file error ,file no exist.")
        return
    try:
        module_name = 'pocs_{0}'.format(get_filename(file_path, with_ext=False))
        spec = util.spec_from_file_location(module_name, file_path)
        mod = util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    except ImportError:
        error_msg = "load module failed! '{}'".format(file_path)
        raise


def get_filename(filepath, with_ext=True):
    base_name = os.path.basename(filepath)
    return base_name if with_ext else os.path.splitext(base_name)[0]
