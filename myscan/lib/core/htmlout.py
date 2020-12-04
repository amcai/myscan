#!/usr/bin/env python3
# @Time    : 2020-02-18
# @Author  : caicai
# @File    : htmlout.py

'''append data:
jsondata={
    "url":"",
    "name":"",
    "create_time":"1582027590342",
    "detail":{
        "vulmsg":"value",
        "key1":"value2"
    }
}
<input type="hidden" class="data-vuln-item" value="base64(jsondata)"/>

like:
<input type="hidden" class="data-vuln-item" value="eyJjcmVhdGVfdGltZSI6MTU4MjAyNzU5MDM0MiwiZGV0YWlsIjp7ImZpbGVuYW1lIjoiLy5naXQvaW5kZXgiLCJob3N0IjoibG9jYWxob3N0IiwicGF5bG9hZCI6IiIsInBvcnQiOjg4ODgsInJlcXVlc3QiOiJHRVQgLy5naXQvaW5kZXggSFRUUC8xLjFcclxuSG9zdDogbG9jYWxob3N0Ojg4ODhcclxuVXNlci1BZ2VudDogTW96aWxsYS81LjAgKE1hY2ludG9zaDsgSW50ZWwgTWFjIE9TIFggMTBfMTRfNCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzc0LjAuMzcyOS4xNjlcclxuQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS93ZWJwLCovKjtxPTAuOFxyXG5BY2NlcHQtTGFuZ3VhZ2U6IHpoLUNOLHpoO3E9MC44LHpoLVRXO3E9MC43LHpoLUhLO3E9MC41LGVuLVVTO3E9MC4zLGVuO3E9MC4yXHJcbkNhY2hlLUNvbnRyb2w6IG1heC1hZ2U9MFxyXG5Db250ZW50LVR5cGU6IHRleHQvcGxhaW5cclxuQ29va2llOiBrZXk9dmFsdWU7IFBIUFNFU1NJRD1rYW02anZnOW00MHZpOXFnampoajRoNG1vNzsgc2VjdXJpdHk9aW1wb3NzaWJsZVxyXG5VcGdyYWRlLUluc2VjdXJlLVJlcXVlc3RzOiAxXHJcbkFjY2VwdC1FbmNvZGluZzogZ3ppcFxyXG5cclxuIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4Ly5naXQvaW5kZXgifSwibmFtZSI6InRlc3QgbmFtZSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODg4OC8uZ2l0L2luZGV4IiwidnVsbl9jbGFzcyI6ImNvZGUifQ=="/>
'''
import json
import base64
import time
import os
from myscan.lib.core.common import getredis
from myscan.lib.core.data import logger, cmd_line_options
from myscan.config import scan_set

import threading
import pickle
import traceback
from myscan.lib.core.options import gethtmlheader


class htmlexport():
    def __init__(self, results, filename):
        self.results = results
        self.outfilename = filename
        self.formatdata = '\n<input type="hidden" class="data-vuln-item" value="{}"/>\n'
        self.level_keys = {
            "-1": "Info",
            "0": "Low",
            "1": "Medium",
            "2": "High",
            "3": "Critical"
        }

    def save(self):
        write_data = ""
        if isinstance(self.results, list) or isinstance(self.results, tuple):
            for result in self.results:
                if isinstance(result, dict):
                    if result:
                        name = str(result.get("name", "unknown name"))
                        url = str(result.get("url", "unknown url"))
                        level = self.getLevel(result.get("level", None))
                        create_time = str(result.get("createtime", "unnknown create_time"))
                        detail = result.get("detail", {})
                        newdetail = {}
                        if detail:
                            for k, v in detail.items():
                                if isinstance(v, bytes) or isinstance(v, bytearray):
                                    newdetail[k] = self.verifyBigData(v.decode("utf-8", errors="ignore"))
                                elif not isinstance(v, str):
                                    newdetail[k] = self.verifyBigData(str(v))
                                else:
                                    newdetail[k] = self.verifyBigData(v)
                        data = {
                            "name": name,
                            "url": url,
                            "level": level,
                            "create_time": create_time,
                            "detail": newdetail
                        }
                        write_data += self.formatdata.format(base64.b64encode(json.dumps(data).encode()).decode())
                    else:
                        logger.warning("result is {},no data to save")
                else:
                    logger.warning("Save result is not dict,result:{}".format(result))
        else:
            logger.warning("Results need be a list or tuple ,you give results:{}".format(self.results))
        if write_data:
            try:
                with open(self.outfilename, "a") as f:
                    f.write(write_data)
                    f.flush()
            except Exception as ex:
                logger.warning("Create file {} get error:{}".format(self.outfilename, ex))

    def getLevel(self, level):
        if level != None:
            if str(level) in self.level_keys.keys():
                return self.level_keys[str(level)]
            else:
                return "Unknown"
        else:
            return "Unknown"

    def verifyBigData(self, text):
        if len(text) > 1024000:
            return "big data,will dont show"
        return text


def writeresults():
    red = getredis()
    total_write = 0
    if "." not in cmd_line_options.html_output:
        cmd_line_options.html_output = cmd_line_options.html_output + ".html"
    while True:
        try:
            results = []
            while True:
                id = red.lpop("vuln_all_write")
                if id:
                    pickle_data = red.get(id)
                    if pickle_data:
                        results.append(pickle.loads(pickle_data))
                else:
                    if results:
                        for result in results:
                            total_write += 1
                            current = int(total_write / scan_set.get("max_html_output", 10))
                            outfilename = "{}{}.html".format('.'.join(cmd_line_options.html_output.split(".")[:-1]),
                                                             current)
                            check(outfilename)
                            out = htmlexport([result], outfilename)
                            out.save()
                            results = []
                    time.sleep(5)
        except KeyboardInterrupt as ex:
            logger.warning("Ctrl+C was pressed ,aborted program")
        except Exception as ex:
            traceback.print_exc()
            logger.warning(ex)
            pass


def start_write_results():
    t = threading.Thread(target=writeresults)
    t.daemon = True
    t.start()


def check(filename):
    if os.path.exists(filename):
        pass
    else:
        try:
            with open(filename, "w") as f:
                f.write(gethtmlheader())
                f.flush()
        except Exception as ex:
            logger.warning("Create file {} get error:{}".format(filename, ex))
