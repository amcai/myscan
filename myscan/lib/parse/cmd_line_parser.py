# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : cmd_line_parser.py
import argparse
import os
import sys


def cmd_line_parser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    _ = os.path.basename(argv[0])
    usage = "myscan [options]"
    parser = argparse.ArgumentParser(prog='myscan', usage=usage)
    try:
        parser.add_argument("command",choices=("webscan","reverse"),type=str, help="select a mode to run ,accept webscan and reverse")
        parser.add_argument("--version", dest="show_version", action="store_true",
                            help="Show program's version number and exit")

        conn = parser.add_argument_group('Connect', "At least one of these "
                                                    "options has to be provided to define the target(s)")
        conn.add_argument("--redis", dest="redis", default="@127.0.0.1:6379:0",
                          help="connect redis host (e.g. \"--redis password@host:port:db\"),default: null@127.0.0.1:6379:0")
        common = parser.add_argument_group('Common', "Config common args")
        # 0:debug 蓝色cyan,1:info 绿色，2:error 黄色，3:critical：红色
        common.add_argument("-v", "--verbose", dest="verbose", type=int, default=1, choices=list(range(4)),
                            help="0 ==> Show :all(debug,info,error,critical .1 ==> Show: info,error,critical 2 ==> Show: error,critical"
                                 "3 ==> Show :critical ")
        common.add_argument("--html-output", dest="html_output", default="myscan_result.html", help="默认myscan_result.html 指定漏洞输出文件")
        common.add_argument("--clean", dest="clean", action="store_true", help="使用此参数可清除Redis所有数据")
        common.add_argument("--check-reverse", dest="check_reverse", action="store_true", help="检测reverse service 是否正常")
        pocs = parser.add_argument_group('pocs', "Config pocs args and pocs to targets")
        pocs.add_argument("--disable", dest="disable", nargs='+', default=[],
                          help="Disable some moudle (e.g. --disable xss sqli un_auth) . you can use '--disable all' to disable all pocs ,default: []")
        pocs.add_argument("--enable", dest="enable", nargs='+', default="*",
                          help="Enable some moudle (e.g. --enable xss sqli un_auth) you can use --enable * ,default: *,please care when you "
                               "use --enable --disable together,will --enable will not take effect")
        pocs.add_argument("--dishost", dest="dishost", nargs='+',
                          default=["baidu.com", "google.com", "firefox.com", "mozilla.org", "bdstatic.com",
                                   "mozilla.com"],
                          help='不扫描主机 .默认"baidu.com","google.com","firefox.com","mozilla.org","bdstatic.com","mozilla.com"')
        pocs.add_argument("--host", dest="host", nargs='+', default=None, help="只扫描的主机,不携带端口")

        controller = parser.add_argument_group('Controller', "")
        controller.add_argument("--threads", dest="threads", type=int, default=2, choices=range(1, 30),
                                help="Yaml Script threads num,default: 10 ")
        controller.add_argument("--process", dest="process", type=int, default=2, choices=range(1, 11),
                                help="Python script process num,default:2")

        request = parser.add_argument_group('Request', "Config request args")
        request.add_argument("--retry", dest="retry", type=int, default=0, help="定义全局request出错后重新尝试请求次数，默认0")
        request.add_argument("--cookie", dest="cookie", default=None, help="测试越权使用cookie，一般为低权限cookie")
        request.add_argument("--timeout", dest="timeout", type=int, default=None,
                             help="定义全局request的超时，默认使用poc脚本自定义超时或request默认超时")
        plugin = parser.add_argument_group('Plugin', "Config plugin args")
        plugin.add_argument("--plugins", dest="plugins", nargs='+', default=None, help="指定插件")

        proxy = parser.add_argument_group('Proxy', "Proxy accept: http,https")
        proxy.add_argument("--proxy", dest="proxy", default=None, help="network proxy,accept host:port,e.g:127.0.0.1:8080")

        args = parser.parse_args()

        return args

    except SystemExit:
        # Protection against Windows dummy double clicking
        pass
        raise
