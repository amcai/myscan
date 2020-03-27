# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : es_export.py
from elasticsearch import helpers
from elasticsearch import Elasticsearch
import base64
import copy
import time


class plugin():
    def __init__(self, dictdata):
        self.dictdata = dictdata
        self.es = Elasticsearch()

    def run(self):
        dictdata=self.dictdata
        # 把请求体和响应体 base64解码，便于搜索
        dictdata["request"]["raw"] = base64.b64decode(self.dictdata.get("request").get("raw")).decode("utf-8",
                                                                                                      errors="ignore")
        dictdata["response"]["raw"] = base64.b64decode(self.dictdata.get("response").get("raw")).decode("utf-8",
                                                                                                   errors="ignore")
        if "others" in dictdata.keys():
            del dictdata["others"]
        if "filter" in dictdata.keys():
            del dictdata["filter"]
        dictdata["ts"]=int(time.time())
        actions = []
        action = {
            "_index": "burpdata",
            "_type": "doc",
            "_source": dictdata
        }
        actions.append(action)
        helpers.bulk(self.es, actions)
