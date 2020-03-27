#!/usr/bin/env python3
# @Time    : 2020-02-27
# @Author  : caicai
# @File    : common.py
import re
from myscan.lib.core.common import get_random_str
from myscan.lib.helper.request import request


def extractScripts(response, xsschecker):
    scripts = []
    matches = re.finditer(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if xsschecker in match.group(1):
            scripts.append((match.group(1),match.start(1)))
    return scripts


def escaped(position, string):

    usable = string[:position][::-1]
    match = re.search(r'^\\*', usable)
    if match:

        match = match.group()
        if len(match) == 1:
            return True
        elif len(match) % 2 == 0:
            return False
        else:
            return True
    else:
        return False


def isBadContext(position, non_executable_contexts):
    badContext = ''
    for each in non_executable_contexts:
        if each[0] < position < each[1]:
            badContext = each[2]
            break
    return badContext


def htmlparser(response, xsschecker):
    '''
    html :{316: {'position': 316, 'context': 'html', 'details': {}}}
    attr :{416: {'position': 416, 'context': 'attribute', 'details': {'tag': 'input', 'type': 'value', 'quote': "'", 'value': 'fuckhaha', 'name': 'value'}}}
    script:

    '''
    reflections = response.count(xsschecker)
    position_and_context = {}
    environment_details = {}
    clean_response = re.sub(r'<!--[.\s\S]*?-->', '', response)
    script_checkable = clean_response
    for script,script_start in extractScripts(script_checkable, xsschecker):
        #找到注释位置
        annotation_positions=[]
        annotation_asterisk = re.finditer(r'(/\*[\s\S]*?\*/)', script, re.S)  # 星号
        for x in annotation_asterisk:
            annotation_positions.append((x.start(), x.start() + len(x.group()), "/*"))
        annotation_backslash=re.finditer(r'(//.*?)$',script,re.M) #正斜杠
        for x in annotation_backslash:
            annotation_positions.append((x.start(),x.start()+len(x.group()),"//"))

        occurences = re.finditer(r'(%s.*?)$' % xsschecker, script,re.M)
        if occurences:
            for occurence in occurences:
                thisPosition = occurence.start(1)+script_start
                position_and_context[thisPosition] = 'script'
                environment_details[thisPosition] = {}
                startwith=script[int(thisPosition)-2:int(thisPosition)]
                environment_details[thisPosition]['details'] = {}
                environment_details[thisPosition]['details']["startwith"]=startwith
                environment_details[thisPosition]['details']['annotation']=''
                #匹配返回值是否在注释里
                for x,y,z in annotation_positions:
                    if x<thisPosition and thisPosition<y:
                        environment_details[thisPosition]['details']["annotation"]=z
                        break
                for i in range(len(occurence.group())):
                    currentChar = occurence.group()[i]
                    if currentChar in ('/', '\'', '`', '"'):

                        environment_details[thisPosition]['details']['quote'] = currentChar
                        break
                    elif currentChar in (')', ']', '}', '}') :
                        break
                script_checkable = script_checkable.replace(xsschecker, '', 1)
    if len(position_and_context) < reflections:
        attribute_context = re.finditer(r'<[^>]*?(%s)[^>]*?>' % xsschecker, clean_response)
        for occurence in attribute_context:
            match = occurence.group(0)
            thisPosition = occurence.start(1)
            parts = re.split(r'\s', match)
            tag = parts[0][1:]
            for part in parts:
                if xsschecker in part:
                    Type, quote, name, value = '', '', '', ''
                    if '=' in part:
                        quote = re.search(r'=([\'`"])?', part).group(1)
                        name_and_value = part.split('=')[0], '='.join(part.split('=')[1:])
                        if xsschecker == name_and_value[0]:
                            Type = 'name'
                        else:
                            Type = 'value'
                        name = name_and_value[0]
                        value = name_and_value[1].rstrip('>').rstrip(quote).lstrip(quote)
                    else:
                        Type = 'flag'
                    environment_details[thisPosition] = {}
                    position_and_context[thisPosition] = 'attribute'
                    environment_details[thisPosition]['details']={}
                    startwith = clean_response[int(thisPosition) - 2:int(thisPosition)]
                    environment_details[thisPosition]['details']['startwith']=startwith
                    environment_details[thisPosition]['details'] = {'tag': tag, 'type': Type, 'quote': quote,
                                                                    'value': value, 'name': name}
    if len(position_and_context) < reflections:
        html_context = re.finditer(xsschecker, clean_response)
        for occurence in html_context:
            thisPosition = occurence.start()
            if thisPosition not in position_and_context:
                position_and_context[occurence.start()] = 'html'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {}
                startwith = clean_response[int(thisPosition) - 2:int(thisPosition)]
                environment_details[thisPosition]['details']['startwith'] = startwith
    if len(position_and_context) < reflections:
        comment_context = re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % xsschecker, response)
        for occurence in comment_context:
            thisPosition = occurence.start(1)
            position_and_context[thisPosition] = 'comment'
            environment_details[thisPosition] = {}
            environment_details[thisPosition]['details'] = {}
            startwith = response[int(thisPosition) - 2:int(thisPosition)]
            environment_details[thisPosition]['details']['startwith'] = startwith
    database = {}
    for i in sorted(position_and_context):
        database[i] = {}
        database[i]['position'] = i
        database[i]['context'] = position_and_context[i]
        database[i]['details'] = environment_details[i]['details']

    bad_contexts = re.finditer(
        r'(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*(%s)[.\s\S]*</\1>' % xsschecker, response)
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])

    if non_executable_contexts:
        for key in database.keys():
            position = database[key]['position']
            badTag = isBadContext(position, non_executable_contexts)
            if badTag:
                database[key]['details']['badTag'] = badTag
            else:
                database[key]['details']['badTag'] = ''
    return database


def check(parser, param, num, payload, random_str, positions, sour, should_show=None):
    '''
    检查param 添加的payload是否可用
    '''
    if not should_show:
        should_show = payload,
    try:
        req=None
        if sour=="url":
            paramsforpayload = parser.setrequesturlorcookie_newvalue(param, "w", payload,
                                                                     urlencode=False,
                                                                     source=sour)
            req = parser.generaterequest({"params": paramsforpayload})

        elif sour=="body":
            paramsforpayload = parser.setrequestbody_newvalue(param, "w", payload, urlencode=False)
            req = parser.generaterequest({"data": paramsforpayload})
        r = request(**req)
        if r!=None:
            if num==-1:
                res = re.search(random_str, r.text)
                if res:
                    return True,r
                else:
                    return False,None
        if r:
            res = re.finditer(random_str, r.text)
            if res:
                res_list = list(res)
                if len(res_list) == len(positions):
                    position_now = res_list[num].start()
                    x = payload.find(random_str)  # 前几位
                    y = len(payload) - x  # 后几位
                    #
                    # if payload[0] in ["'\""] and r.text[position_now-x-1] =="\\": #这里有个bug，会造成5%的误报，根据payload前2位比较基本完美
                    #     return False,None
                    now_show = r.text[position_now - x:position_now + y]
                    # print("now:{},should:{}".format(now_show, should_show))
                    if now_show.lower() in [show_.lower() for show_ in should_show]:  # quote+> lengths=2
                        return True, r
                #这里有个else，根据大概位置匹配
    except Exception as ex:
        print("run xss check error:{}".format(ex))
    return False, None
