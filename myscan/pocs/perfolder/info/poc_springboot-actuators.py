# !/usr/bin/env python3
# @Time    : 2020/8/20
# @Author  : caicai
# @File    : myscan_springboot-actuators.py

from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options
from myscan.lib.core.common import get_random_str, similar, get_error_page


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "springboot-actuators"
        self.vulmsg = "find sensitive msg"
        self.level = 3  # 0:Low  1:Medium 2:High
        self.max_similar = 0.9
        self.error_page = get_error_page(self.dictdata)

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        # print(self.error_page)
        # return
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return

        paths = ["actuator",
                 "actuator/auditevents",
                 "actuator/auditLog",
                 "actuator/beans",
                 "actuator/caches",
                 "actuator/conditions",
                 "actuator/configprops",
                 "actuator/configurationMetadata",
                 "actuator/dump",
                 "actuator/env",
                 "actuator/events",
                 "actuator/exportRegisteredServices",
                 "actuator/features",
                 "actuator/flyway",
                 "actuator/healthcheck",
                 "actuator/heapdump",
                 "actuator/httptrace",
                 "actuator/hystrix.stream",
                 "actuator/integrationgraph",
                 "actuator/jolokia",
                 "actuator/liquibase",
                 "actuator/logfile",
                 "actuator/loggers",
                 "actuator/loggingConfig",
                 "actuator/management",
                 "actuator/mappings",
                 "actuator/metrics",
                 "actuator/refresh",
                 "actuator/registeredServices",
                 "actuator/releaseAttributes",
                 "actuator/resolveAttributes",
                 "actuator/scheduledtasks",
                 "actuator/sessions",
                 "actuator/shutdown",
                 "actuator/springWebflow",
                 "actuator/sso",
                 "actuator/ssoSessions",
                 "actuator/statistics",
                 "actuator/status",
                 "actuator/threaddump",
                 "actuator/trace",
                 "auditevents",
                 "autoconfig",
                 "beans",
                 "cloudfoundryapplication",
                 "configprops",
                 "dump",
                 "env",
                 "heapdump",
                 "hystrix.stream",
                 "jolokia",
                 "jolokia/list",
                 "loggers",
                 "management",
                 "mappings",
                 "metrics",
                 "threaddump",
                 "trace",
                 ]
        mythread(self.check, paths, cmd_line_options.threads)

    def check_second(self, path, raw):
        random_str = get_random_str(4).lower()
        path = random_str + path
        req = {
            "method": "GET",
            "url": self.url + path,
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        if r is not None and self.max_similar > similar(raw, r.content):
            return True

    def check(self, path):
        req = {
            "method": "GET",
            "url": self.url + path,
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        # words = [
        #     "method",
        #     "spring",
        #     "TYPE",
        #     "system",
        #     "database",
        #     "cron",
        #     "reloadByURL",
        #     "JMXConfigurator",
        #     "JMImplementation",
        #     "EnvironmentManager",
        # ]
        words_header = ["X-Application-Context",
                        "application/json",
                        "application/vnd.spring-boot.actuator",
                        "hprof",
                        ]
        # if r is not None and r.status_code == 200 and any(
        #         [x.encode() in r.content for x in words] and [x in str(r.headers) for x in words_header]):
        if r is not None and r.status_code == 200 and any([x in str(r.headers) for x in words_header]) and similar(
                r.content, self.error_page) < self.max_similar:
            if self.check_second(path, r.content):
                parser_ = response_parser(r)
                self.result.append({
                    "name": self.name,
                    "url": self.url + path,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "request": parser_.getrequestraw(),
                        "response": parser_.getresponseraw()
                    }
                })
