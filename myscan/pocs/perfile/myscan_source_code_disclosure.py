# !/usr/bin/env python3
# @Time    : 2020/11/5
# @Author  : caicai
# @File    : myscan_source_code_disclosure.py

'''

from awvs:
Scripts/PostCrawl/Server_Source_Code_Disclosure.script
'''
from myscan.lib.helper.request import request
from myscan.lib.core.common import similar, get_random_str
from myscan.lib.core.data import cmd_line_options
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.threads import mythread
# from myscan.lib.core.const import acceptedExt
import os, re
from urllib import parse


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "source_code_disclosure"
        self.vulmsg = "no details"
        self.level = 1  # 0:Low  1:Medium 2:High
        self.found = False

    def verify(self):
        # 添加限定条件
        acceptedExt = ["php", "php3", "php4", "php5", "asp", "aspx", "jsp", "cfm", "pl", "shtml"]
        if self.dictdata.get("url").get("extension").lower() not in acceptedExt:
            return
        dirname = self.dictdata.get("url").get("path_folder")
        basename = os.path.basename(self.dictdata.get("url").get("path", ""))
        filename, ext = os.path.splitext(basename)
        ariants = [
            filename + "/%3f." + ext,
            filename + ext.upper(),
            filename + ext[:-1] + parse.quote(ext[-1]),
            filename + "%252e" + ext,
            basename + ".%E2%73%70",
            basename + "%2easp",
            basename + "%2e",
            basename + "\\",
            basename + "?*",
            basename + "+",
            basename + "%20",
            basename + "%00",
            basename + "%01",
            basename + "%2f",
            basename + "%5c",
            basename + ".htr",
            basename + "::DATA"
        ]
        self.regexs = [
            "(\<%[\s\S]*Response\.Write[\s\S]*%\>)",
            "(\<\?php[\x20-\x80\x0d\x0a\x09]+)",
            "(^#\!\\\/[\s\S]*\\\/perl)",
            "(^#\!\/[\s\S]*?\/python)",
            "(^#\!\/usr\/bin\/env\spython)",
            "(^#\!\/[\s\S]*?\/perl)",
            "using\sSystem[\s\S]*?class\s[\s\S]*?\s?{[\s\S]*}"
        ]
        self.regexWhitelist = [
            "([^0-9a-zA-Z]+bxss\.me[^0-9a-zA-Z]+)",
            "([^0-9a-zA-Z]+r87\.me[^0-9a-zA-Z]+)",
            "(bnNsb29rdXAgbXFpc3d2dHh0c[a-zA-Z0-9]+5yODcubWU)"

        ]
        paths = [os.path.join(dirname, x) for x in ariants]
        mythread(self.send_req, paths, cmd_line_options.threads)

    def send_req(self, path):
        req = {
            "method": "GET",
            "url": "",
            "timeout": 10,
            "verify": False,
            "allow_redirects": False,
        }
        req["url"] = path
        if self.found:
            return
        r = request(**req)
        if r is not None and r.status_code == 200:
            content = r.content[:1000]
            for regex in self.regexs:
                if re.search(regex.encode(), content, re.I):
                    #     if any([re.search(x.encode(), content, re.I) for x in self.regexWhitelist]):
                    #         pass
                    #     else:
                    #         self.found = True
                    #         self.save(r,regex)
                    # 先看哈效果，感觉awvs的白名单没啥用
                    self.found = True
                    self.save(r, regex)

    def save(self, r, regex):
        parser = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser.geturl(),
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "regex": regex,
                "request": parser.getrequestraw(),
                "response": parser.getresponseraw(),
            }
        })
