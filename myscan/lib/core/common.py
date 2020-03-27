#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : common.py
import os
import redis
from random import sample
from urllib import parse
import sys
from myscan.lib.core.data import paths, conn, cmd_line_options,logger
import difflib
import hashlib
import base64


def redis_conn():
    arg_redis = cmd_line_options.redis
    if arg_redis:
        if "@" in arg_redis:
            pwd, ipport = arg_redis.split("@", 1)
            if not pwd:
                pwd = None
            if ":" in ipport and ipport.count(".") >= 2:
                ip, port, db = ipport.split(":", 2)
            else:
                ip = ipport
                port = 6379
                db = 0
            logger.info("Redis connection args: pwd:{},ip:{},port:{},db:{}".format(pwd, ip, port, db))
            conn.redis = redis.ConnectionPool(host=ip, password=pwd, port=int(port), db=int(db))
            red=getredis()


    else:
        # error_msg = "Set reids connection error,please check redis-server"
        error_msg = "Please use --redis pass@host:port:db ,if pass is none ,like --redis @host:port:db"
        logger.warning(error_msg)
        sys.exit()
def set_paths(root_path):
    """
    Sets absolute paths for project directories and files
    """
    paths.MYSCAN_ROOT_PATH = root_path
    paths.MYSCAN_DATA_PATH = os.path.join(paths.MYSCAN_ROOT_PATH, "data")
    paths.MYSCAN_PLUGINS_PATH = os.path.join(paths.MYSCAN_ROOT_PATH, "plugins")
    # paths.MYSCAN_MOUDLE_PATH = os.path.join(paths.MYSCAN_ROOT_PATH, "moudle")
    paths.MYSCAN_POCS_PATH = os.path.join(paths.MYSCAN_ROOT_PATH, "pocs")
    paths.MYSCAN_REPORT_PATH = os.path.join(paths.MYSCAN_ROOT_PATH, "report")
    paths.USER_POCS_PATH = None

    paths.SENSETIVE_DIR = os.path.join(paths.MYSCAN_DATA_PATH, "sensetive-dir.txt")
    paths.WEAK_PASS = os.path.join(paths.MYSCAN_DATA_PATH, "password-top100.txt")
    paths.LARGE_WEAK_PASS = os.path.join(paths.MYSCAN_DATA_PATH, "password-top1000.txt")

    # paths.MYSCAN_HOME_PATH = os.path.expanduser("~")
    # _ = os.path.join(paths.MYSCAN_HOME_PATH, ".pocsuite")
    #
    # paths.API_SHELL_HISTORY = os.path.join(_, "api.hst")
    # paths.OS_SHELL_HISTORY = os.path.join(_, "os.hst")
    # paths.SQL_SHELL_HISTORY = os.path.join(_, "sql.hst")
    # paths.MYSCAN_SHELL_HISTORY = os.path.join(_, "pocsuite.hst")
    # paths.MYSCAN_CONSOLE_HISTORY = os.path.join(_, "console.hst")
    #
    # paths.MYSCAN_TMP_PATH = os.path.join(_, "tmp")
    # paths.MYSCAN_RC_PATH = os.path.join(paths.MYSCAN_HOME_PATH, ".pocsuiterc")
    # paths.MYSCAN_OUTPUT_PATH = paths.get("MYSCAN_OUTPUT_PATH", os.path.join(_, "output"))


def get_random_str(nums):
    return ''.join(sample("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", int(nums)))


def get_random_num(nums):
    return int(''.join(sample("123456789", int(nums))))


def banner():
    return "\033[1;33;40m" + '''
#  .___  ___. ____    ____  _______.  ______      ___      .__   __. 
#  |   \/   | \   \  /   / /       | /      |    /   \     |  \ |  | 
#  |  \  /  |  \   \/   / |   (----`|  ,----'   /  ^  \    |   \|  | 
#  |  |\/|  |   \_    _/   \   \    |  |       /  /_\  \   |  . `  | 
#  |  |  |  |     |  | .----)   |   |  `----. /  _____  \  |  |\   | 
#  |__|  |__|     |__| |_______/     \______|/__/     \__\ |__| \__| 
#                                                               v2.0                                                                                                  
    ''' + "\033[0m"


def similar(text1, text2):
    return difflib.SequenceMatcher(None, text1, text2).quick_ratio()


def getredis():
    #此处windows linux的一个坑，windows不能多进程 共享socket

    return redis.StrictRedis(connection_pool=conn.redis)


def gethostportfromurl(url):
    '''
    return list [host,port]
    '''
    port = 80
    r = parse.urlparse(url)
    if ":" not in r.netloc:
        if r.scheme == "https":
            port = 443
    else:
        h, p = r.netloc.split(":")
        return h, int(p)
    return r.netloc, port
def getmd5(s):
    m = hashlib.md5()
    if not isinstance(s,str):
        s=str(s)
    b = s.encode(encoding='utf-8')
    m.update(b)
    return m.hexdigest()
def is_base64(value: str):
    if isinstance(value,str):
        value=value.encode()
    try:
        res=base64.b64decode(value)
        return res.decode().isprintable()
    except Exception as ex:
        print(ex)
        return False
def verify_param(param,new,method="a"):
    '''
    处理新添加的值
    burp大哥这么说的:
     /**
     * Used to indicate a parameter within the URL query string.
     */
    static final byte PARAM_URL = 0;
    /**
     * Used to indicate a parameter within the message body.
     */
    static final byte PARAM_BODY = 1;
    /**
     * Used to indicate an HTTP cookie.
     */
    static final byte PARAM_COOKIE = 2;
    /**
     * Used to indicate an item of data within an XML structure.
     */
    static final byte PARAM_XML = 3;
    /**
     * Used to indicate the value of a tag attribute within an XML structure.
     */
    static final byte PARAM_XML_ATTR = 4;
    /**
     * Used to indicate the value of a parameter attribute within a multi-part
     * message body (such as the name of an uploaded file).
     */
    static final byte PARAM_MULTIPART_ATTR = 5;
    /**
     * Used to indicate an item of data within a JSON structure.
     */
    static final byte PARAM_JSON = 6;
    '''
    if param.get("type")==1:   #body,主动url编码
        if method=="a":
            value=parse.quote(parse.unquote(param.get("value"))+new)
        else:
            value=parse.quote(new)
        return value
    if param.get("type") in [0,2]:   #cookie ,url ，request会自动url编码
        if method=="a":
            value=parse.unquote(param.get("value"))+new
        else:
            value=new
        return value
    if param.get("type")>2: #xml,json等不编码，按理说json要把"等转义，后头再弄
        if method=="a":
            value=param.get("value")+new
        else:
            value=new
        return value





