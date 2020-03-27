#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : log.py
import logging
import sys


class Logger(object):
    def __init__(self, logger):
        """
        指定保存日志的文件路径，日志级别，以及调用文件
        将日志存入到指定的文件中
        :param logger:  定义对应的程序模块名name，默认为root
        """

        # 创建一个logger
        self.logger = logging.getLogger(name=logger)
        self.logger.setLevel(logging.DEBUG)  # 指定最低的日志级别 critical > error > warning > info > debug

        # 创建一个handler，用于输出到控制台
        ch = logging.StreamHandler(sys.stdout)

        # 定义handler的输出格式
        formatter = logging.Formatter(
            "%(asctime)s - %(message)s", "%Y-%m-%d-%H:%M:%S")
        # formatter = logging.Formatter(
        #     "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
        # )
        ch.setFormatter(formatter)

        # 给logger添加handler
        # self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def debug(self, msg, text="DEBUG"):
        """
        定义输出的颜色debug--white，info--green，warning/error/critical--red
        :param msg: 输出的log文字
        :return:
        """
        # self.logger.debug(Fore.CYAN + "[DEBUG] - " + str(msg) + Style.RESET_ALL)
        self.logger.debug("\033[0;36;40m" + "[{}] - ".format(text) + str(msg).strip() + "\033[0m")

    def critical(self, msg, text="SUCCESS"):
        # self.logger.info(Fore.RED + "[SUCCESS] - " + str(msg) + Style.RESET_ALL)
        self.logger.critical("\033[0;31;40m" + "[{}] - ".format(text) + str(msg).strip() + "\033[0m")

    def warning(self, msg, text="WARNING"):
        # self.logger.warning(Fore.YELLOW + "[WARNING] - " + str(msg) + Style.RESET_ALL)
        self.logger.warning("\033[0;33;40m" + "[{}] - ".format(text) + str(msg).strip() + "\033[0m")

    # def error(self, msg):
    #     self.logger.error(Fore.RED + "[ERROR] - " + str(msg) + Style.RESET_ALL)

    def info(self, msg, text="INFO"):
        # self.logger.critical(Fore.GREEN + "[INFO] - " + str(msg) + Style.RESET_ALL)
        self.logger.info("\033[0;32;40m" + "[{}] - ".format(text) + str(msg).strip() + "\033[0m")
