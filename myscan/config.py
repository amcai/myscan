# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : config.py

version = "2.0.0"

# 配置一些扫描参数
scan_set = {
    "max_dir": 2,  # should >=1 ,某些脚本需要最大目录变量，url域名后有多少/ ，就代表当前url目录深度，如http://www.baidu.com/test/tset，目录深度为2,
    "status_flush_time": 3,  # 控制台刷新状态的时间，默认单位秒
    "search_open": True,  # 是否开放搜索模式
    "search_maxout": 3,  # 某种vulmsg条目最大输出数
    "poc_timeout": 1800,  # 单位秒,单个poc运行超时时间,默认1800秒，即30分钟,防止进程阻塞
    "block_count": 500,  # 默认500，如果host:poort的最新500次请求均失败，则会把host:port加入黑名单
    "random_test": True,  # 是否随机从任务池子选择任务，适合高配置服务器，为True时，redis内存会变大，但是工作是随机，防止短时间大量对统一主机请求。
    "max_html_output": 120,  # 一个html报告中最大的漏洞条数，如果超过则会新建html，如result1.html
}

# 配置一些poc languages 插件参数
plugin_set = {
    "xss": {
        "use_low_level": True,  # 当脚本无法检测出payload时候，是否提示存在枚举的可能性。
    },
    "power": {  # 权限插件，如果碰到token等，也可再下方添加，原始请求包上，如果不存在则添加， 存在则替换
        "cookie": "",  # 自定义越权poc的cookie
    },
    "sqli": {  # 目前只能配置time_blind
        "level": 0,  # 0-1,0:将使用' " 空格闭合，1将在0基础上增加) ') ")闭合
        "header_inject": True,  # 进行UA，Referer,XFF,XFH,Real-IP注入
    },
    "ssti": {
        "level": 0,  # 0-5 ，建议 0,越往后数据包越多，个别fuzz情况可配置大一些
    },
    "dirscan": {  # 此选项根据字典大小,比较耗时
        "dirfile": "",  # 目录字典位置,绝对路径,默认 myscanroot/data/dir/dicc.txt
        "doamin_dict": True  # 是否根据域名生成备份文件字典测试,会增加字典1700余条
    }

}

# 配置反连平台 参考doc/Class1-关于被动扫描器.md的反连平台部分
reverse_set = {
    "reverse_http_ip": "203.195.199.146",  # http服务ip，一般和reverse_domain的a记录一致。
    "reverse_http_port": 9999,  # http服务端口
    "reverse_domain": "log.evilhex.top",
    "reverse_rmi_ip": "203.195.199.146",  # rmi服务ip，一般和http地址一致。
    "reverse_rmi_port": 10002,  # rmi服务端口
    "reverse_ldap_ip": "203.195.199.146",  # ldap服务ip，一般和http地址一致。
    "reverse_ldap_port": 10003,  # ldap服务端口
    # 配置ns的域名，如log.evilhex.top的ns记录指向testns.evilhex.top，testns.evilhex.top的a记录指向203.195.199.146。
    "secret_key": "haha,zheshiyigehenfuzademima",  # 客户端访问服务器密码，如果不配置，则随机密码，最好配置一下，不然客户端也得配置
    "db_file": "reverse.db",  # 所有http和dns记录均会保存在sqlite3的dbfile内。
    "sleep": 5,  # 客户端攻击后，睡眠时间再去服务端取结果时候，默认s，建议3-5s。
}

db_set = {
    "es_open": False,
    "es_addr": ["127.0.0.1:9200"],
    "es_auth": ('', ''),  # 默认空密码
    "es_uniq":False
}
