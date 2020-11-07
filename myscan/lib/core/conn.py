#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : conn.py
import sys
from myscan.lib.core.data import conn, cmd_line_options, logger, others
from myscan.lib.core.common import getredis, redis_conn
from myscan.config import db_set
from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections


def set_conn():
    try:

        redis_conn()
        red = getredis()
        if not red.ping():
            error_msg = "redis ping error . will exit program"
            logger.warning(error_msg)
            sys.exit()
        else:
            logger.info("Redis ping success")
    except Exception as ex:
        error_msg = " connnect redis get error {}:please use --redis pass@host:port:db ,if pass is none ,like --redis @host:port:db".format(
            ex)
        logger.warning(error_msg)
        sys.exit()

    # TODO 其他连接方式


def cleandb():
    # red = redis.StrictRedis(connection_pool=conn.redis)
    red = getredis()
    if None in red.hmget("count_all", "doned", "request", "block_host", "request_fail"):
        count_all = {
            "block_host": 0,  # 被封的host_port
            'doned': 0,  # 已经做过的burpdata条数
            "request": 0,  # request 次数
            "request_fail": 0,  # request fail次数
            "active": 0,  # 正在工作的poc数
        }
        red.hmset("count_all", count_all)
    if cmd_line_options.clean:
        red.flushall()
        count_all = {
            "block_host": 0,  # 被封的host_port
            'doned': 0,  # 已经做过的burpdata条数
            "request": 0,  # request 次数
            "request_fail": 0,  # request fail次数
            "active": 0,  # 正在工作的poc数
        }
        red.hmset("count_all", count_all)


def set_es_conn():
    if db_set.get("es_open"):
        try:
            client = connections.create_connection(hosts=db_set.get("es_addr"),
                                                   http_auth=db_set.get("es_auth"), timeout=10)
            info = client.info()
            if "You Know, for Search" in str(info):
                if int(info.get("version").get("number").replace(".", "")) > 700:
                    logger.info("Success connect es : {}".format(db_set.get("es_addr")))
                    others.es_conn = client
                    set_httpinfo()
                else:
                    logger.warning("Your es version should be > 7.0.0")
                    sys.exit()
        except Exception as ex:
            logger.warning("es conn get error :{} , will exit program".format(ex))
            logger.warning(
                "if you don't want to use elasticsearch .please config 'es_open':False, in config.py".format(ex))
            sys.exit()


def set_httpinfo():
    body = {'settings': {'analysis': {
        'char_filter': {'replace_slash_to_null': {'type': 'pattern_replace', 'pattern': '/', 'replacement': ' '},
                        'get_root_domain': {'type': 'pattern_replace', 'pattern': '^.+?\\.([0-9a-z\\-]+\\.[a-z]+)$',
                                            'replacement': '$1'},
                        "replace_realdomain_to_true": {
                            "type": "pattern_replace",
                            "pattern": "^.*?\\.[a-z]+$",
                            "replacement": "true"
                        },
                        "replace_ipdomain_to_false": {
                            "type": "pattern_replace",
                            "pattern": "^.*?\\.[0-9]{1,3}$",
                            "replacement": "false"
                        }
                        },
        'tokenizer': {'tokenizer_slash': {'type': 'pattern', 'pattern': '/'},
                      'tokenizer_dot': {'type': 'pattern', 'pattern': '\\.'}},
        "normalizer": {
            "root_domain_keyword": {
                "type": "custom",
                "char_filter": "get_root_domain",
                "filter": [
                    "lowercase"
                ]
            },
            "verify_is_domain": {
                "type": "custom",
                "char_filter": ["replace_realdomain_to_true", "replace_ipdomain_to_false"],
                "filter": [
                    "lowercase"
                ]
            }
        },
        'analyzer': {'analyzer_path': {'type': 'custom', 'tokenizer': 'tokenizer_slash', 'filter': ['lowercase']},
                     'analyzer_host': {'type': 'custom', 'tokenizer': 'tokenizer_dot', 'filter': ['lowercase']},
                     'analyzer_domain': {'type': 'custom', 'tokenizer': 'whitespace', 'char_filter': 'get_root_domain',
                                         'filter': ['lowercase']}}}}, 'mappings': {'date_detection': False,
                                                                                   'dynamic_templates': [{
                                                                                       'request_raw': {
                                                                                           'path_match': 'request.raw',
                                                                                           'mapping': {
                                                                                               'type': 'text',
                                                                                               'analyzer': 'ik_max_word'}}},
                                                                                       {
                                                                                           'response_raw': {
                                                                                               'path_match': 'response.raw',
                                                                                               'mapping': {
                                                                                                   'type': 'text'
                                                                                                   }}},
                                                                                       {
                                                                                           'request_headers': {
                                                                                               'path_match': 'request.headers',
                                                                                               'mapping': {
                                                                                                   'type': 'text'
                                                                                                   }}},
                                                                                       {
                                                                                           'response_headers': {
                                                                                               'path_match': 'response.headers',
                                                                                               'mapping': {
                                                                                                   'type': 'keyword',
                                                                                                   'ignore_above': 256}}},
                                                                                       {'url_path': {
                                                                                           'path_match': 'url.path',
                                                                                           'mapping': {
                                                                                               'type': 'text',
                                                                                               'analyzer': 'analyzer_path',
                                                                                               'fields': {
                                                                                                   'keyword': {
                                                                                                       'type': 'keyword',
                                                                                                       'ignore_above': 500}}}}},
                                                                                       {'url_host': {
                                                                                           'path_match': 'url.host',
                                                                                           'mapping': {
                                                                                               'type': 'text',
                                                                                               'analyzer': 'analyzer_host',
                                                                                               'fields': {
                                                                                                   'keyword': {
                                                                                                       'type': 'keyword',
                                                                                                       'ignore_above': 256},

                                                                                                   'domain': {
                                                                                                       'type': 'keyword',
                                                                                                       'normalizer': 'root_domain_keyword',
                                                                                                       'ignore_above': 256,
                                                                                                   },
                                                                                                   "isdomain": {
                                                                                                       "type": "keyword",
                                                                                                       "normalizer": "verify_is_domain"
                                                                                                   }
                                                                                               }}}},

                                                                                       {'url_url': {
                                                                                           'path_match': 'url.url',
                                                                                           'mapping': {
                                                                                               'type': 'keyword',
                                                                                               'ignore_above': 1000}}},
                                                                                       {
                                                                                           'url_protocol': {
                                                                                               'path_match': 'url.protocol',
                                                                                               'mapping': {
                                                                                                   'type': 'keyword',
                                                                                                   'ignore_above': 256}}},
                                                                                       {'url_port': {
                                                                                           'path_match': 'url.port',
                                                                                           'mapping': {
                                                                                               'type': 'integer'}}},
                                                                                       {
                                                                                           'url_pathroot': {
                                                                                               'path_match': 'url.path_root',
                                                                                               'mapping': {
                                                                                                   'type': 'keyword',
                                                                                                   'ignore_above': 256}}},
                                                                                       {
                                                                                           'url_extension': {
                                                                                               'path_match': 'url.extension',
                                                                                               'mapping': {
                                                                                                   'type': 'keyword',
                                                                                                   'ignore_above': 256}}},
                                                                                       {'url_ip': {
                                                                                           'path_match': 'url.ip',
                                                                                           'mapping': {
                                                                                               'type': 'keyword',
                                                                                               'ignore_above': 256}}},
                                                                                       {'url_icon': {
                                                                                           'path_match': 'url.icon_hash',
                                                                                           'mapping': {
                                                                                               'type': 'keyword'}}}],
                                                                                   'properties': {'ts': {'type': 'date',
                                                                                                         'format': 'epoch_millis'
                                                                                                         },
                                                                                                  'source': {
                                                                                                      'type': 'keyword',
                                                                                                      'ignore_above': 256}}}}
    index = "httpinfo"
    if not others.es_conn.indices.exists(index):
        logger.warning("elasticsearch not exist :{} , will create it".format(index))
        if others.es_conn.indices.create(index=index, body=body).get("acknowledged"):
            logger.info("elasticsearch create {} success".format(index))
        else:
            logger.warning("elasticsearch create {} failed , will exit program".format(index))
            sys.exit()
