#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : myscan_sensitive_file_leak.py
import re
from myscan.lib.helper.request import request
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options


tests = [

    {"path": "phpinfo.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},
    {"path": "pi.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},
    {"path": "i.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},
    {"path": "info.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},
    {"path": "test.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},
    {"path": "php.php", "contains": b"PHP Extension|<title>phpinfo()</title>",
     "vulmsg": "phpinfo() file leak . can leak some php version and abs path and sensitive message."},

    {"path": ".svn/all-wcprops", "contains": b"svn:wc:ra_dav:version-url",
     "vulmsg": ".svn leak"},
    {"path": ".svn/entries", "contains": b"\s+dir\s*\d+\s*",
     "vulmsg": ".svn leak"},

    {"path": ".git/config", "contains": b"repositoryformatversion[\s\S]*",
     "vulmsg": ".git leak"},
    {"path": ".bzr/README", "contains": b"This\sis\sa\sBazaar[\s\S]",
     "vulmsg": ".brz leak"},
    {"path": "CVS/Root", "contains": b":pserver:[\s\S]*?:[\s\S]*",
     "vulmsg": "csv leak"},
    {"path": ".hg/requires", "contains": b"^revlogv1.*",
     "vulmsg": ".hg leak"},
    {"path": ".DS_Store", "contains": b"\x42\x75\x64\x31",
     "vulmsg": ".DS_Store file leak . can leak some directory tree."},
    {"path": ".idea/workspace.xml", "contains": b'<project version="\w+">',
     "vulmsg": "JetBrans .idea leak"},
    {"path": ".htaccess",
     "contains": b'(RewriteEngine|RewriteCond|RewriteRule|AuthType|AuthName|AuthUserFile|ErrorDocument|deny from|AddType|AddHandler|IndexIgnore|ContentDigest|AddOutputFilterByType|php_flag|php_value)\s',
     "vulmsg": "SFTP_Credentials_Exposure leak"},
    {"path": "sftp-config.json", "contains": b'("type":[\s\S]*?"host":[\s\S]*?"user":[\s\S]*?"password":[\s\S]*")',
     "vulmsg": "sftp-config  leak"},
    {"path": "recentservers.xml", "contains": b'filezilla',
     "vulmsg": "filezilla config  leak"},
    {"path": ".config/filezilla/recentservers.xml", "contains": b'filezilla',
     "vulmsg": "filezilla config  leak"},
    {"path": "swagger-ui.html", "contains": b'<title>Swagger UI</title>',
     "vulmsg": "api leak"},
    {"path": "crossdomain.xml", "contains": b'<?xml ',
     "vulmsg": "crossdomain.xml leak","level":0},

]


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")
        self.url = workdata.get("data")
        self.result = []
        self.name = "file leak"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        mythread(self.poc, tests, cmd_line_options.threads)

    def poc(self, info):
        try:

            if self.url.count("/") <= info.get("max_dir", 999) + 2:
                req = {
                    "method": "GET",
                    "url": self.url + info.get("path"),
                    "headers": self.dictdata.get("request").get("headers"),
                    "timeout": 5,
                    "verify": False,
                    "allow_redirects": False,
                }
                r = request(**req)
                if r != None:
                    if str(r.status_code).startswith("20") and re.search(info.get("contains"), r.content, re.I | re.S):
                        self.result.append({
                            "name": self.name,
                            "url": self.url + info.get("path"),
                            "level": self.level if info.get("level",None)==None else info.get("level"),
                            "detail": {
                                "vulmsg": info.get("vulmsg"),
                            }
                        })
        except Exception as ex:
            print("run dirleak get error:" + str(ex))
