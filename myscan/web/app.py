#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import redis
import pickle
from flask import Flask, request, render_template

ROWS_PER_PAGE = 20
app = Flask(__name__)



@app.route('/')
def index():
    print(request.remote_addr)
    total_counts=SearchFromRedis('all',countonly=True)
    return render_template('index.html', total_counts=total_counts["total_rows"], title=u'被动扫描器平台')
@app.route('/search', methods=['get'])
def search():
    keywords = request.args.get('keywords','all')
    page = int(request.args.get('page', '1'))
    size = int(request.args.get('size', '10'))
    page_info=SearchFromRedis(keywords,size=size,page=page)
    if not page_info["total_rows"]==0:
        return render_template('search1.html', keywords=keywords, page_info=page_info,title=u'搜索结果')
    else:
        return render_template("error.html")


def SearchFromRedis(rule_name,countonly=False,size=10,page=1):
    size=int(size)
    page=int(page)
    if page<1:
        page=1
    rule_name="vuln_"+rule_name if not rule_name.startswith("vuln_") else rule_name
    # red=redis.Redis(host="127.0.0.1",db=0,password="123")
    red=redis.Redis(host="127.0.0.1",db=0)

    alldata={
        "rows":[],
        "total_rows":0
    }
    total_rows=red.llen(rule_name)
    if total_rows==0:
        return {
            "size":0,
            "total_rows":0
        }

    if size >total_rows:
        size=10
    alldata["size"]=size
    alldata["total_rows"]=total_rows
    total_pages=int((int(total_rows) /int(size))) +1
    if int(total_rows) %int(size) ==0:
        total_pages-=1
    alldata["total_pages"] = total_pages

    if page>total_pages:
        page=total_pages
    alldata["current_page"]=page
    if page==1:
        key_start,key_end=0,9
    else:
        key_start, key_end = (page-1)*size, page*size-1
    # all["rows"]
    if not countonly:
        ids=red.lrange(rule_name,key_start,key_end)
        num=1
        for id in ids:
            vul_data=pickle.loads(red.get(id))
            # print(vul_data)
            detail={}
            if vul_data["detail"]:
                for k,v in vul_data["detail"].items():
                    if isinstance(v,bytes):
                        detail[k]=v.decode("utf-8",errors="ignore")
                    else:
                        detail[k]=v
            alldata["rows"].append(
                {
                    "num":str(num),
                    "vulntype":vul_data["name"],
                    "url":vul_data["url"],
                    "createtime":vul_data["createtime"],
                    "detail":detail
                    # "request_raw":vul_data["detail"]["request_raw"],
                    # "response_raw":vul_data["detail"]["response_raw"],
                    # "rule_source":vul_data["detail"]["rule_source"]

                }
            )
            num=num+1
    return alldata


def main():
    port = 5000
    app.run(host='0.0.0.0', port = port, debug=True, threaded=True)

if __name__ == '__main__':
    main()

