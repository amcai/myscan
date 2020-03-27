#!/usr/bin/env python3
# @Time    : 2020-02-23
# @Author  : caicai
# @File    : reverse_http.py

import time, binascii, json
from flask import Flask, request, g
from myscan.config import reverse_set
from myscan.lib.core.common_reverse import TABLE, connect_db
from myscan.lib.core.data import logger
from myscan.lib.core.common_reverse import insert_db

app = Flask(__name__)


@app.before_request
def before_request():
    g.db = connect_db()


@app.after_request
def after_request(response):
    g.db.close()
    return response


@app.route('/',methods=["GET","POST","PUT","HEAD","DELETE"])  #http 的reverse 接收端,支持众多方法一些poc使用post方法等
def index():
    data = request.args.get("d", None)
    if data:
        try:
            info = ""
            try:
                info = binascii.a2b_hex(data[4:].encode()).decode()
            except:
                pass
            res = {}
            res["type"] = "http"
            res["client"] = request.remote_addr
            res["query"] = data
            res["info"] = info
            res["time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            logger.info("Insert to db:" + str(res))
            insert_db(res)
            return json.dumps({"status": "success"})
        except Exception as ex:
            logger.warning("process index d get error:{}".format(ex))
            pass
    return json.dumps({"status": "fail", "reason": ""})


@app.route('/search', methods=["GET"])
def search():
    q = request.args.get("query", None)
    k = request.args.get("key", None)
    if q:
        if k == app.config["secret_key"]:
            res = {}
            res["status"] = "success"
            if q=="myscan_total":
                cur = g.db.execute(
                'select type, client, info,query,time from {} order by id desc'.format(TABLE))
            else:
                cur = g.db.execute(
                'select type, client, info,query,time from {} where query like ? order by id desc'.format(TABLE), (q+"%",))

            total = cur.fetchall()
            res["total"] = len(total)
            if q=="myscan_total":
                res["data"]=[]
            else:
                res["data"] = [dict(type=row[0], client=row[1], info=row[2], query=row[3], time=row[4]) for row in total]
            logger.info("Out to client:{}".format(res))
            return json.dumps(res)
        else:
            return json.dumps({"status": "fail", "reason": "secret_key is not right"})
    return json.dumps({"status": "fail", "reason": ""})


def http_start(secret_key):
    app.config["secret_key"] = secret_key
    port = int(reverse_set.get("reverse_http_port"))
    app.run(host='0.0.0.0', port=port)
