#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : myscan_sensitive_file_leak.py
import re
from myscan.lib.helper.request import request
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options
from myscan.lib.parse.response_parser import response_parser


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")
        self.url = workdata.get("data")
        self.result = []
        self.name = "file leak"
        self.level = 1  # 0:Low  1:Medium 2:High
        self.basedir = self.url.count("/")
        self.tests = [

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
            {"path": "manager/html", "contains": b"conf/tomcat-users.xml",
             "vulmsg": "tomcat manager leak", "state_code": 401},
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
             "vulmsg": ".htaccess leak", "state_code": "2"},
            {"path": "sftp-config.json",
             "contains": b'("type":[\s\S]*?"host":[\s\S]*?"user":[\s\S]*?"password":[\s\S]*")',
             "vulmsg": "sftp-config  leak"},
            {"path": "recentservers.xml", "contains": b'filezilla',
             "vulmsg": "filezilla config  leak"},
            {"path": "swagger-ui.html", "contains": b'<title>Swagger UI</title>',
             "vulmsg": "api leak"},
            # {"path": "crossdomain.xml", "contains": b'<\?xml ',
            #  "vulmsg": "crossdomain.xml leak","level":0},
            {"path": "console/login/LoginForm.jsp", "contains": b"Oracle WebLogic Server",
             "vulmsg": "you can access /console to brute user password", "level": 1},
            {"path": "conf/context.xml", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "context.xml leak"},
            {"path": "conf/web.xml", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "web.xml leak"},
            {"path": "manager/status.xsd", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "status.xsd leak"},
            {"path": "conf/server.xml", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "server.xml leak"},
            {"path": "conf/context.xml", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "context.xml leak"},
            {"path": "conf/logging.properties", "contains": b"org.apache.catalina",
             "vulmsg": "context.xml leak"},
            {"path": "conf/tomcat-users.xml", "contains": b"^<\?xml version.*?Licensed to the Apache Software Foundation",
             "vulmsg": "tomcat-users.xml leak"},
            {"path": "apc/apc.php",
             "contains": b"(APCu Version Information)|(General Cache Information)|(Detailed Memory Usage and Fragmentation)",
             "vulmsg": "APCu service information leakage", "max_dir": 3},
            {"path": "apc.php",
             "contains": b"(APCu Version Information)|(General Cache Information)|(Detailed Memory Usage and Fragmentation)",
             "vulmsg": "APCu service information leakage", "max_dir": 3},
            {"path": "cgi-bin/test/test.cgi", "contains": b"HTTP_ACCEPT.*?HTTP_ACCEPT_ENCODING",
             "vulmsg": "CGI Test page", "max_dir": 3},
            {"path": "debug/pprof/", "contains": b"Types of profiles available",
             "vulmsg": "pprof debug file", "max_dir": 3},
            {"path": "install.php?profile=default", "contains": b"<title>Choose language \| Drupal</title>",
             "vulmsg": "pprof debug file", "max_dir": 3},
            {"path": "Reports/Pages/Folder.aspx", "contains": b"Report Manager",
             "vulmsg": "Detect Microsoft SQL Server Reporting", "max_dir": 3},
            {"path": "console", "contains": b"<h1>Interactive Console</h1>",
             "vulmsg": "Werkzeug debugger console", "max_dir": 3},
            {"path": "irj/portal", "contains": b"NetWeaver",
             "vulmsg": "SAP NetWeaver Detect", "max_dir": 3},
            {"path": "%c0", "contains": b"InvalidURI|InvalidArgument|NoSuchBucket",
             "vulmsg": "Detect Amazon-S3 Bucket", "max_dir": 3},
            {"path": "secure/Dashboard.jspa", "contains": b"Project Management Software",
             "vulmsg": "Detect Jira Issue Management Software", "max_dir": 3},
            {"path": "jira/secure/Dashboard.jspa", "contains": b"Project Management Software",
             "vulmsg": "Detect Jira Issue Management Software", "max_dir": 3},
            {"path": "settings.py", "contains": b"TEMPLATES",
             "vulmsg": "django settings.py leak", "max_dir": 3},
            {"path": "vpn/index.html", "contains": b"<title>Citrix Gateway</title>",
             "vulmsg": "Citrix VPN Detection", "max_dir": 3},
            # {"path": "crossdomain.xml", "contains": b"allow-access-from domain=\"*\"",
            #  "vulmsg": "Basic CORS misconfiguration exploitable with Flash", "max_dir": 3},
            {"path": "?phpinfo=-1",
             "contains": b'xdebug.remote_connect_back</td><td class="v">On</td><td class="v">On</td>',
             "vulmsg": "WAMP xdebug", "max_dir": 3},
            {"path": "?pp=env", "contains": b'Rack Environment',
             "vulmsg": "rack-mini-profiler environmnet information discloure", "max_dir": 3, "state_code": 200},
            {"path": "secure/popups/UserPickerBrowser.jspa", "contains": b'user-picker',
             "vulmsg": "Jira Unauthenticated User Picker", "max_dir": 3},
            {"path": "secure/ManageFilters.jspa?filter=popular&filterView=popular", "contains": b'filterlink_',
             "vulmsg": "Jira Unauthenticated Popular Filters", "max_dir": 3},
            {"path": "dispatcher/invalidate.cache", "contains": b'<H1>OK</H1>',
             "vulmsg": "Jira Unauthenticated Popular Filters", "max_dir": 3,"state_code": "200"},

        ]

    def verify(self):
        mythread(self.poc, self.tests, cmd_line_options.threads)

    def poc(self, info):
        try:
            if self.basedir <= info.get("max_dir", 999) + 2:
                req = {
                    "method": "GET",
                    "url": self.url + info.get("path"),
                    "headers": self.dictdata.get("request").get("headers"),
                    "timeout": 10,
                    "verify": False,
                    "allow_redirects": False,
                }
                r = request(**req)
                if r != None:
                    # if info.get("state_code"):
                    #     if not str(r.status_code).startswith(str(info.get("state_code"))):
                    #         return
                    # res = str(r.status_code).startswith(str(info.get("state_code"))) if info.get("state_code") else str(
                    #     r.status_code).startswith("2")
                    res = str(r.status_code).startswith(str(info.get("state_code"))) if info.get("state_code") else True
                    if res and re.search(info.get("contains"), r.content, re.I | re.S):
                        parser_ = response_parser(r)
                        self.result.append({
                            "name": self.name,
                            "url": self.url + info.get("path"),
                            "level": self.level if info.get("level", None) == None else info.get("level"),
                            "detail": {
                                "vulmsg": info.get("vulmsg"),
                                "response": parser_.getresponseraw()
                            }
                        })
        except Exception as ex:
            print("run dirleak get error:" + str(ex))
