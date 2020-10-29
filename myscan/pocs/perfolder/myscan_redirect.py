# !/usr/bin/env python3
# @Time    : 2020/9/18
# @Author  : caicai
# @File    : myscan_redirect.py
'''
未验证
'''
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options
import re


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "redirect"
        self.vulmsg = "A user-controlled input redirect users to an external website"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        swffile = [
            'evil.com/',
            '//;@evil.com',
            '//evil.com/%2F..',
            '////evil.com',
            '/evil.com/%2F..',
            '/evil.com/..;/css',
            'evil%E3%80%82com',
            '%5Cevil.com',
            # '?Page=evil.com&_url=evil.com&callback=evil.com&checkout_url=evil.com&content=evil.com&continue=evil.com&continueTo=evil.com&counturl=evil.com&data=evil.com&dest=evil.com&dest_url=evil.com&dir=evil.com&document=evil.com&domain=evil.com&done=evil.com&download=evil.com&feed=evil.com&file=evil.com&host=evil.com&html=evil.com&http=evil.com&https=evil.com&image=evil.com&image_src=evil.com&image_url=evil.com&imageurl=evil.com&include=evil.com&media=evil.com&navigation=evil.com&next=evil.com&open=evil.com&out=evil.com&page=evil.com&page_url=evil.com&pageurl=evil.com&path=evil.com&picture=evil.com&port=evil.com&proxy=evil.com&redir=evil.com&redirect=evil.com&redirectUri&redirectUrl=evil.com&reference=evil.com&referrer=evil.com&req=evil.com&request=evil.com&retUrl=evil.com&return=evil.com&returnTo=evil.com&return_path=evil.com&return_to=evil.com&rurl=evil.com&show=evil.com&site=evil.com&source=evil.com&src=evil.com&target=evil.com&to=evil.com&uri=evil.com&url=evil.com&val=evil.com&validate=evil.com&view=evil.com&window=evil.com&redirect_to=evil.com',
        ]

        mythread(self.test, swffile, cmd_line_options.threads)

    def test(self, path):
        req = {
            "method": "GET",
            # payload :    "])}catch(e){if(!window.x){window.x=1;alert("xss")}}
            "url": self.url + path,
            "timeout": 10,
            "allow_redirects": False,
            "verify": False,
        }
        r = request(**req)
        if r is not None and str(r.status_code).startswith("3"):
            localtion = r.headers.get("Location", "").split("?")[0].strip()
            if re.search("^(//|https?://)([a-zA-Z0-9\-_]*\.)*evil.com", localtion):
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
