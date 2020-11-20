#!/usr/bin/env python3
# @Time    : 2020-04-20
# @Author  : caicai
# @File    : myscan_ssti.py

'''
payload 来自 tplmap,未添加bind的payload.
'''
from myscan.lib.core.data import others, cmd_line_options
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.threads import mythread


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "ssti "
        self.vulmsg = "模板注入，某些情况可获取shell"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.found_flag = []

    def verify(self):
        if self.dictdata.get("url").get("extension")[:3].lower() not in ["", "php", "do", "action"]:
            return
        self.parser = dictdata_parser(self.dictdata)

        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        if params:
            for param in params:
                thread_datas = [(param, test_payload) for test_payload in others.ssti_payloads]
                mythread(self.inject, thread_datas, cmd_line_options.threads)

    def inject(self, data):
        param, test_payload = data
        payload, show, plugin = test_payload
        # # 是php后缀，但是plugin不是php框架，不测试
        # if self.dictdata.get("url").get("extension")[:3].lower() in ["", "php"]:
        #     if plugin.lower() not in ["php", "smarty", "twig"]:
        #         return

        flag = "{name}---{type}".format(**param)
        if flag in self.found_flag:
            # 此参数已经有结果了，不用测试
            return
        req = self.parser.getreqfromparam(param, "w", payload)
        r = request(**req)
        if r != None and show.encode() in r.content:
            parser_ = response_parser(r)
            self.found_flag.append(flag)
            self.result.append({
                "name": self.name,
                "url": parser_.geturl(),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "plugin": plugin,
                    "param": param.get("name"),
                    "payload": payload,
                    "should_show": show,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })


'''
dot http://127.0.0.1:15004/dot?inj=*&tpl=%s
dust http://127.0.0.1:15004/dust?inj=*&tpl=%s 
ejs http://127.0.0.1:15004/ejs?inj=*&tpl=%s
erb http://localhost:15005/reflect/erb?inj=*&tpl=%s True 采用乘法
freemarker http://127.0.0.1:15003/freemarker?inj=*&tpl=%s
Jinja2  http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*
mako http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*
marko http://127.0.0.1:15004/marko?inj=*&tpl=%s
nunjucks http://127.0.0.1:15004/nunjucks?inj=*&tpl=%s
pug http://127.0.0.1:15004/pug?inj=*&tpl=%s
slim http://localhost:15005/reflect/slim?inj=*&tpl=%s True 采用乘法
smarty http://127.0.0.1:15002/smarty-3.1.32-secured.php?inj=*&tpl=%s  True 用注释拼接字符
tornado http://127.0.0.1:15001/reflect/tornado?tpl=%s&inj=*  True 拼接字符
twig http://127.0.0.1:15002/twig-1.20.0-secured.php?tpl=%s&inj=* True 采用输出字符+<br >
velocity http://127.0.0.1:15003/velocity?inj=*&tpl=%s  True 采用输出数据类型+数字
javascript http://127.0.0.1:15004/javascript?inj=*&tpl=%s True 采用类型和数字
php http://localhost:15002/eval.php?inj=*&tpl=%s True 采用md5
ruby http://localhost:15005/reflect/eval?inj=*&tpl=%s  True 采用乘法
python http://localhost:15001/reflect/eval?inj=*&tpl=%s True  采用拼接字符
'''
