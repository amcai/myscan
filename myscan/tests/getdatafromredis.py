#!/usr/bin/env python3
# @Time    : 2020-06-09
# @Author  : caicai
# @File    : getdatafromredis.py

import redis, json
r = redis.Redis(db=0)
res = r.lpop("burpdata")
if res:
    print(json.dumps(json.loads(res),indent=3))
