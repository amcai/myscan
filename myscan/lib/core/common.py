#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : common.py
import os
import redis
import re
import ipaddress
from random import sample
from urllib import parse
import sys
from myscan.lib.core.data import paths, conn, cmd_line_options, logger
import difflib
import hashlib
import base64
import json
import requests


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
            conn.redis = redis.ConnectionPool(max_connections=300, host=ip, password=pwd, port=int(port), db=int(db))
            red = getredis()


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
    paths.MYSCAN_HOSTSCAN_BIN = os.path.join(paths.MYSCAN_ROOT_PATH, "lib", "bin")
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
    return int(''.join(sample("123456789" * (int(nums // 9) + 1), int(nums))))


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


def similar(text1, text2, strict=False):
    '''
    strict默认为了减小内存开销，为False,对于一般情况来说够准确了。
    '''
    if strict:
        return difflib.SequenceMatcher(None, text1, text2).quick_ratio()
    min_len = min(len(text1), len(text2))
    return difflib.SequenceMatcher(None, text1[:min_len], text2[:min_len]).quick_ratio()


def getredis():
    return redis.StrictRedis(connection_pool=conn.redis)


def gethostportfromurl(url):
    '''
    return list [host,port]
    '''
    port = 80
    r = parse.urlparse(url)
    netloc = re.search(r"(^[0-9a-z\-\.]+$)|(^[0-9a-z\-\.]+:\d+)", r.netloc, re.I)
    if netloc:
        netloc = netloc.group()
        if ":" not in netloc:
            if r.scheme == "https":
                port = 443
        else:
            h, p = netloc.split(":", 1)
            return h, int(p)
        return r.netloc, port

    return url, 0


def getmd5(s):
    m = hashlib.md5()
    if not isinstance(s, str):
        s = str(s)
    b = s.encode(encoding='utf-8')
    m.update(b)
    return m.hexdigest()


def is_base64(value):
    '''
    return : bytes or False
    '''
    if isinstance(value, str):
        value = value.encode()
    if len(value) % 4 != 0:
        return False
    regx = b'^[a-zA-Z0-9+/=%]+$'
    if not re.match(regx, value):
        return False

    try:
        res = base64.b64decode(value)
        return res
    except Exception as ex:
        # print(ex)
        return False


def escapeJsonValue(value):
    value = str(value)
    """
    Escapes JSON value (used in payloads)

    # Reference: https://stackoverflow.com/a/16652683
    """

    retVal = ""

    for char in value:
        if char < ' ' or char == '"':
            retVal += json.dumps(char)[1:-1]
        else:
            retVal += char

    return retVal


def verify_param(param, new, method="a", body=b"", bodyoffset=0, isvalue=True):
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
    if isinstance(new, bytes) or isinstance(new, bytearray):
        new = new.decode()
    if not isinstance(new, str):
        new = str(new)
    if param.get("type") == 1:  # body,主动url编码
        if method == "a":
            if isvalue:
                value = parse.quote(parse.unquote(param.get("value")) + new)
            else:
                value = parse.quote(parse.unquote(param.get("name", "")) + new)
        else:
            value = parse.quote(new)
        return value
    if param.get("type") in [0, 2]:  # cookie ,url ，request会自动url编码
        if method == "a":
            if isvalue:
                value = parse.unquote(param.get("value")) + new
            else:
                value = parse.unquote(param.get("name", "")) + new
        else:
            value = new
        return value
    if param.get("type") in [3, 4, 5]:
        if method == "a":
            if isvalue:
                value = param.get("value") + new.replace('>', "&gt;").replace('<', "&lt;")
            else:
                value = param.get("name", "") + new.replace('>', "&gt;").replace('<', "&lt;")
        else:
            value = new.replace('>', "&gt;").replace('<', "&lt;")
        return value
    if param.get("type") == 6:
        if isvalue:
            s_value = param.get("value", "")
        else:
            s_value = param.get("name", "")
        st = param.get("valuestart") - bodyoffset
        symbol = body[st - 1:st]
        if symbol == b'"':
            if method == "a":
                value = s_value + escapeJsonValue(new)
            else:
                value = escapeJsonValue(new)
            return value
        else:
            double_str = '"'
            if method == "a":
                value = double_str + s_value + escapeJsonValue(new) + double_str
            else:
                value = double_str + escapeJsonValue(new) + double_str

            return value


def is_ipaddr(host):
    '''
    判断是否是ip格式
    '''
    try:
        ipaddress.ip_address(str(host))
        return True
    except Exception as ex:
        return False


def get_error_page(dictdata, allow_redirects=False, extension=""):
    red = getredis()
    key = "error_page_{protocol}_{host}_{port}_{ext}".format(**dictdata["url"], ext=extension)
    res = red.get(key)
    if res:
        return res
    else:
        req = {
            "method": "GET",
            "url": "{protocol}://{host}:{port}/".format(**dictdata["url"]) + get_random_str(6) + extension,
            "timeout": 10,
            "verify": allow_redirects,
            "allow_redirects": False
        }
        r = None
        try:
            r = requests.request(**req)
        except:
            pass
        if r is not None:
            red.set(key, r.content)
            return r.content


def isjson(arg, quote=True):
    '''
    arg: string
    '''
    try:
        if arg.isdigit():
            return False
        if not arg:
            return False
        if quote:
            arg = parse.unquote(arg)
        return json.loads(arg)
    except:
        return False


def check_echo(s, r1, r2):
    success = False
    for search in re.finditer(("%s(.{1,10})%s" % (r1, r2)).encode(), s):
        start = search.start()
        spacedata = search.groups()[0]
        space_echo = s[start - len(spacedata):start] if start > len(spacedata) else s[0:start]
        if space_echo != spacedata:
            space_echo = s[start - len(b"echo" + spacedata):start] if start > len(b"echo" + spacedata) else s[0:start]
            if space_echo != b"echo" + space_echo:
                success = True
                break
    return success
