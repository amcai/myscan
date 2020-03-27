#!/usr/bin/env python3
# @Time    : 2020-02-20
# @Author  : caicai
# @File    : utils.py
# refer:https://github.com/s0md3v/XSStrike
import re
import copy
import random
from fuzzywuzzy import fuzz
from myscan.lib.helper.request import request
from myscan.lib.scriptlib.xss.const import xsschecker


def randomUpper(string):
    return ''.join(random.choice((x, y)) for x, y in zip(string.upper(), string.lower()))


def genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=None):
    vectors = []
    r = randomUpper  # randomUpper randomly converts chars of a string to uppercase
    for tag in tags:
        if tag == 'd3v' or tag == 'a':
            bait = xsschecker
        else:
            bait = ''
        for eventHandler in eventHandlers:
            # if the tag is compatible with the event handler
            if tag in eventHandlers[eventHandler]:
                for function in functions:
                    for filling in fillings:
                        for eFilling in eFillings:
                            for lFilling in lFillings:
                                for end in ends:
                                    if tag == 'd3v' or tag == 'a':
                                        if '>' in ends:
                                            end = '>'  # we can't use // as > with "a" or "d3v" tag
                                    breaker = ''
                                    if badTag:
                                        breaker = '</' + r(badTag) + '>'
                                    vector = breaker + '<' + r(tag) + filling + r(
                                        eventHandler) + eFilling + '=' + eFilling + function + lFilling + end + bait
                                    vectors.append(vector)
    return vectors


def fillHoles(original, new):
    filler = 0
    filled = []
    for x, y in zip(original, new):
        if int(x) == (y + filler):
            filled.append(y)
        else:
            filled.extend([0, y])
            filler += (int(x) - y)
    return filled


def replaceValue(mapping, old, new, strategy=None):
    """
    Replace old values with new ones following dict strategy.

    The parameter strategy is None per default for inplace operation.
    A copy operation is injected via strateg values like copy.copy
    or copy.deepcopy

    Note: A dict is returned regardless of modifications.
    """
    anotherMap = strategy(mapping) if strategy else mapping
    if old in anotherMap.values():
        for k in anotherMap.keys():
            if anotherMap[k] == old:
                anotherMap[k] = new
    return anotherMap


def extractScripts(response):
    scripts = []
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if xsschecker in match:
            scripts.append(match)
    return scripts


def isBadContext(position, non_executable_contexts):
    badContext = ''
    for each in non_executable_contexts:
        if each[0] < position < each[1]:
            badContext = each[2]
            break
    return badContext


def equalize(array, number):
    if len(array) < number:
        array.append('')


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


def htmlParser(response):
    # rawResponse = response  # raw response returned by requests
    # response = response.text  # response content
    reflections = response.count(xsschecker)
    position_and_context = {}
    environment_details = {}
    clean_response = re.sub(r'<!--[.\s\S]*?-->', '', response)
    script_checkable = clean_response
    for script in extractScripts(script_checkable):
        occurences = re.finditer(r'(%s.*?)$' % xsschecker, script)
        if occurences:
            for occurence in occurences:
                thisPosition = occurence.start(1)
                position_and_context[thisPosition] = 'script'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {'quote': ''}
                for i in range(len(occurence.group())):
                    currentChar = occurence.group()[i]
                    if currentChar in ('/', '\'', '`', '"') and not escaped(i, occurence.group()):
                        environment_details[thisPosition]['details']['quote'] = currentChar
                    elif currentChar in (')', ']', '}', '}') and not escaped(i, occurence.group()):
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
                    position_and_context[thisPosition] = 'attribute'
                    environment_details[thisPosition] = {}
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
    if len(position_and_context) < reflections:
        comment_context = re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % xsschecker, response)
        for occurence in comment_context:
            thisPosition = occurence.start(1)
            position_and_context[thisPosition] = 'comment'
            environment_details[thisPosition] = {}
            environment_details[thisPosition]['details'] = {}
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


# def checker(url, params, headers, GET, delay, payload, positions, timeout, encoding):
def checker(req, payload, positions, payload_from="url"):
    '''
    payload_from : accept url body and cookie
    '''
    checkString = 'st4r7s' + payload + '3nd'
    if payload_from.lower() == "url":
        new_params = {}
        params = copy.deepcopy(req.get("params"))
        for k, v in params.items():
            if xsschecker == v:
                new_params[k] = checkString
            else:
                new_params[k] = v
        req["params"] = new_params
        print("params:{}".format(new_params))
    if payload_from.lower() == "body":
        req["data"] = bytearray(req.get("data")).replace(xsschecker.encode(), checkString.encode())
        print("body:{}".format(req["data"]))
    r = request(**req)
    if not r:
        return []
    response = r.text.lower()
    reflectedPositions = []
    for match in re.finditer('st4r7s', response):
        reflectedPositions.append(match.start())
    filledPositions = fillHoles(positions, reflectedPositions)
    #  Itretating over the reflections
    num = 0
    efficiencies = []
    for position in filledPositions:
        allEfficiencies = []
        try:
            reflected = response[reflectedPositions[num]
                                 :reflectedPositions[num] + len(checkString)]
            efficiency = fuzz.partial_ratio(reflected, checkString.lower())
            allEfficiencies.append(efficiency)
        except IndexError:
            pass
        if position:
            reflected = response[position:position + len(checkString)]
            efficiency = fuzz.partial_ratio(reflected, checkString)
            if reflected[:-2] == ('\\%s' % checkString.replace('st4r7s', '').replace('3nd', '')):
                efficiency = 90
            allEfficiencies.append(efficiency)
            efficiencies.append(max(allEfficiencies))
        else:
            efficiencies.append(0)
        num += 1
    return list(filter(None, efficiencies))


def filterChecker(req, occurences, payload_from="url"):
    positions = occurences.keys()
    sortedEfficiencies = {}
    # adding < > to environments anyway because they can be used in all contexts
    environments = set(['<', '>'])
    for i in range(len(positions)):
        sortedEfficiencies[i] = {}
    for i in occurences:
        occurences[i]['score'] = {}
        context = occurences[i]['context']
        if context == 'comment':
            environments.add('-->')
        elif context == 'script':
            environments.add(occurences[i]['details']['quote'])
            environments.add('</scRipT/>')
        elif context == 'attribute':
            if occurences[i]['details']['type'] == 'value':
                if occurences[i]['details']['name'] == 'srcdoc':  # srcdoc attribute accepts html data with html entity encoding
                    environments.add('&lt;')  # so let's add the html entity
                    environments.add('&gt;')  # encoded versions of < and >
            if occurences[i]['details']['quote']:
                environments.add(occurences[i]['details']['quote'])
    print("environments :len:{}".format(len(environments)))
    for environment in environments:
        if environment:
            req_copy=copy.deepcopy(req)
            efficiencies = checker(req_copy, environment, positions, payload_from)
            efficiencies.extend([0] * (len(occurences) - len(efficiencies)))
            for occurence, efficiency in zip(occurences, efficiencies):
                occurences[occurence]['score'][environment] = efficiency
    return occurences
