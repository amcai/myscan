# !/usr/bin/env python3
# @Time    : 2020/7/30
# @Author  : caicai
# @File    : from_json_import.py


import json


def get_data_from_jsonfile(filename):
    datas = []
    with open(filename, errors="ignore") as f:
        lines = f.readlines()
        for line in lines:
            try:
                dic = json.loads(line.strip())
                datas.append(
                    {
                        "filter": dic.get("filter", True),
                        "scan": dic.get("scan", False),
                        "addr": str(dic.get("addr")),
                        "port": int(dic.get("port")),
                        "type": dic.get("type", "tcp"),
                        "service": dic.get("service")
                    }
                )

            except Exception as e:
                print("process get_data_from_jsonfile error: {}".format(e))
    return datas
