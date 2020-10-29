# !/usr/bin/env python3
# @Time    : 2020/8/20
# @Author  : caicai
# @File    : poc_webeditor_found.py
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options
class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "webeditor_found"
        self.vulmsg = "to more step"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        paths = [
            "fckeditor/_samples/default.html",
            "ckeditor/samples/",
            "editor/ckeditor/samples/",
            "ckeditor/samples/sample_posteddata.php",
            "editor/ckeditor/samples/sample_posteddata.php",
            "fck/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php",
            "fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellcheckder.php",
            "ueditor/php/getRemoteImage.php",
                 ]
        mythread(self.check, paths, cmd_line_options.threads)

    def check(self, path):
        req = {
            "method": "GET",
            "url": self.url + path,
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        words = [
            "<title>FCKeditor",
            "<title>CKEditor Samples</title>",
            "ckeditor.com</a>",
            "init_spell()",
            "'tip':'",
        ]
        if r is not None and any(
                [x.encode() in r.content for x in words]):
            parser_ = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
