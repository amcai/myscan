# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : cli.py
import os
import sys

try:
    import myscan
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from myscan.lib.core.common import set_paths
from myscan.lib.core.conn import set_conn, cleandb
from myscan.lib.core.options import init_options
from myscan.lib.controller.start import process_start, start
from myscan.lib.core.status import start_count_status
from myscan.lib.core.htmlout import start_write_results
from myscan.lib.core.data import cmd_line_options, logger
from myscan.reverse.reverse import reverse_start
from myscan.lib.hostscan.start_input import start_input


def main():
    set_paths(os.path.dirname(os.path.realpath(__file__)))
    init_options()
    if cmd_line_options.command in ["webscan","hostscan"] :
        logger.info("Start {} mode".format(cmd_line_options.command))
        set_conn()
        cleandb()
        start_count_status()
        start_write_results()
        start_input()
        process_start()
        start()
    elif cmd_line_options.command == "reverse":
        logger.info("Start reverse mode")
        reverse_start()

if __name__ == '__main__':
    main()
