#!/usr/bin/env python3
# @Time    : 2020-02-20
# @Author  : caicai
# @File    : jsContexter.py

import re

from myscan.lib.scriptlib.xss.const import xsschecker


def stripper(string, substring, direction='right'):
    done = False
    strippedString = ''
    if direction == 'right':
        string = string[::-1]
    for char in string:
        if char == substring and not done:
            done = True
        else:
            strippedString += char
    if direction == 'right':
        strippedString = strippedString[::-1]
    return strippedString


def jsContexter(script):
    broken = script.split(xsschecker)
    pre = broken[0]
    #  remove everything that is between {..}, "..." or '...'
    pre = re.sub(r'(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'', '', pre)
    breaker = ''
    num = 0
    for char in pre:  # iterate over the remaining characters
        if char == '{':
            breaker += '}'
        elif char == '(':
            breaker += ';)'  # yes, it should be ); but we will invert the whole thing later
        elif char == '[':
            breaker += ']'
        elif char == '/':
            try:
                if pre[num + 1] == '*':
                    breaker += '/*'
            except IndexError:
                pass
        elif char == '}':  # we encountered a } so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, '}')
        elif char == ')':  # we encountered a ) so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, ')')
        elif breaker == ']':  # we encountered a ] so we will strip off "our }" because this one does the job
            breaker = stripper(breaker, ']')
        num += 1
    return breaker[::-1]  # invert the breaker string
