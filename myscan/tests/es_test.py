# !/usr/bin/env python3
# @Time    : 2020/9/1
# @Author  : caicai
# @File    : es_test.py

from  elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections
from elasticsearch import helpers

client = connections.create_connection(hosts=['127.0.0.1:9200'],
    http_auth=('',''), timeout=10)
info=client.info()
if "You Know, for Search" in str(info):
    if int(info.get("version").get("number").replace(".",""))>700:
        action = {
            "_index": "burpdata",
            "_id": "111111",
            "_source": {"a":1}
        }
        client.indices.exists("httpinfo")
        helpers.bulk(client, [action])
