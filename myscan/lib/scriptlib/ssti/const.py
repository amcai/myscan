#!/usr/bin/env python3
# @Time    : 2020-04-20
# @Author  : caicai
# @File    : const.py
from myscan.lib.core.common import get_random_num
rand_long1=get_random_num(10)
rand_long2=get_random_num(10)
rand1=get_random_num(3)
rand2=get_random_num(3)
rand3=get_random_num(3)
jinja2={
    'render' : {
                    'render': '{{%(code)s}}',
                    'header': '{{%(header)s}}',
                    'trailer': '{{%(trailer)s}}',
                    'test_render': '(%(n1)s,%(n2)s*%(n3)s)' % {
                        'n1' : rand1,
                        'n2' : rand2,
                        'n3' : rand3
                    },
                    'test_render_expected': '%(res)s' % {
                        'res' : (rand1,rand2*rand3)
                    }
                },
}

def generate_payload():
    payloads=[]
    for render in [jinja2]:
        r_=render.get("render")
        p=r_.get("header")%({"header":rand_long1})+r_.get("render")%({"code":r_.get("test_render")})+r_.get("trailer")%({"trailer":rand_long2})
        payloads.append(
            (p,r_.get("test_render_expected"))
                        )
    return payloads
