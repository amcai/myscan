# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : config.py

version = "2.0"

# 配置一些扫描参数
scan_set = {
    "max_dir": 2,  # should >=1 ,某些脚本需要最大目录变量，url域名后有多少/ ，就代表当前url目录深度，如http://www.baidu.com/test/tset，目录深度为2,
    "status_flush_time": 5,  # 控制台刷新状态的时间，默认单位秒
    "search_open": True,  # 是否开放搜索模式
    "block_count": 150,  # 达到封锁次数的阀值,根据host:port未能连接的次数计算，数值需小于等于200
}

# 配置一些poc plugin 插件参数
plugin_set = {
    "xss":{
        "use_low_level":True, #当脚本无法检测出payload时候，是否提示存在枚举的可能性。
    },
    "power":{          # 权限插件，如果碰到token等，也可再下方添加，原始请求包上，如果不存在则添加， 存在则替换
        "cookie": "",  # 自定义越权poc的cookie
    },

}

# 配置反连平台
reverse_set = {
    "reverse_http_ip": "203.195.199.146",  # http服务ip，一般和reverse_domain的a记录一致。
    "reverse_http_port": 9999,  # http服务端口
    "reverse_domain": "log.evilhex.top",
    "reverse_rmi_ip": "203.195.199.146",  # rmi服务ip，一般和http地址一致。
    "reverse_rmi_port": 10002,  # rmi服务端口
    # 配置ns的域名，如log.evilhex.top的ns记录指向testns.evilhex.top，testns.evilhex.top的a记录指向203.195.199.146。
    "secret_key": "haha,zheshiyigehenfuzademima",  # 客户端访问服务器密码，如果不配置，则随机密码，最好配置一下，不然客户端也得配置
    "db_file": "reverse.db",  # 所有http和dns记录均会保存在sqlite3的dbfile内。
    "sleep": 5,  # 客户端攻击后，睡眠时间再去服务端取结果时候，默认s，建议3-5s。
}
