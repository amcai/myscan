# !/usr/bin/env python3
# @Time    : 2020/7/22
# @Author  : caicai
# @File    : myscan_dirscan.py

'''
可根据域名生成备份文件
自定义字典

算法支持：
1. 先匹配一个错误页面的内容，每个路径的内容和错误页面内容相似度比较
2. 旧路径和新路径相似度比较，如 路径 /admin/admin.php 会和 /admin/adminwsdk.php 页面内容比较相似度
# 3.特定关键词 ,此处未实现（未收集）

dirsearch的核心匹配也是匹配相识度，加上remove静态的字段，保留动态的字符串进行比较，虽然精确度很高，但是此功能对于被动扫描来说，
不可遇见的因素如返回包几百M的等不确定因素太大了，容易模块卡死，考虑简单的，但是误报比较大,这个可以慢慢调整嘛。
'''

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.config import scan_set, plugin_set
from myscan.lib.core.data import others, logger, cmd_line_options
from myscan.lib.core.common import is_ipaddr, get_random_str, similar
from myscan.lib.core.threads import mythread
import os


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "dirscan"
        self.vulmsg = "leak info"
        self.level = 1  # 0:Low  1:Medium 2:High
        self.exts_bak = [".gz", ".tar.gz", ".tar", ".zip", ".7z", ".rar", ".bak", ".backup", ".bz2", ".lz", ".sqlite",
                         ".sqlitedb", ".sql.7z", ".sql.rar", ".sql.zip"]
        self.found_path = set()

    def verify(self):
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        # 生成字典
        self.similar_rate = 0.8  # 相似度 ,越大误报越高
        self.parser = dictdata_parser(self.dictdata)
        self.rootpath = self.parser.getrootpath()
        self.dicc = list(set(others.url_dict_path + self.get_domain_backfile(self.dictdata.get("url").get("host"))))
        self.error_content = self.check_url(get_random_str(10), verify=False)
        mythread(self.run, self.dicc, cmd_line_options.threads)

    def get_domain_backfile(self, host):
        '''
        生成域名字典
        '''
        bakfiles = []
        if not plugin_set.get("dirscan").get("doamin_dict") or is_ipaddr(host):
            return bakfiles

        startswith_ = ['config', 'error', '2018', 'build', '2016', 'test', 'php', '打包', 'index', '0', '4',
                       'other_vhosts_access', 'web', 'src', '9', '2017', 'output', '123', 'mysql', '2013', '8', 'conf',
                       'weblog', 'shop', 'elk', 'redis', 'deploy', 'backupdatabase', 'a', 'ftp', 'cgi', 'package',
                       '2020', '备份', '7', '2011', 'www2', 'www4', 'www1', 'default', 'website', 'host', 'bin', 'jsp',
                       'tmp', 'upload', 'sql', 'backup', '2012', '源码', 'code', 'WebRoot', '6', 'webserver', 'db',
                       'data', '2', 'install', 'admin', 'wwwroot', 'webroot', 'logs', '2019', 'log', '5', 'access',
                       'old', 'logo', 'back', 'bbs', 'temp', 'kibana', '2014', '2015', 'wwww', '3', '1', '网站', 'aa',
                       'www', 'www3', 'dump']
        hostlist = host.split(".")
        startswith_ += [host]
        startswith_ += hostlist[:-1]
        startswith_ += ["".join(hostlist)]
        startswith_ += [".".join(hostlist[1:])]
        startswith_ += [".".join(hostlist[:-1])]
        for s in list(set(startswith_)):
            for e in self.exts_bak:
                bakfiles.append(s.lower() + e)
                # bakfiles.append(s.upper() + e)
                # bakfiles.append(s.capitalize() + e)
        return list(set(bakfiles))

    def check_url(self, path, verify=True):
        if not path.startswith("/"):
            path = "/" + path
        # url = self.rootpath + path
        url = self.url[:-1] + path
        req = self.parser.generaterequest({"url": url, "method": "GET"})
        r = request(**req)
        if r is not None:
            if verify:
                if r.status_code == 200:
                    # 根据错误页面相似度比较
                    if self.error_content is not None:
                        if similar(self.error_content, r.content) > self.similar_rate:
                            return False
                    #
                    args = ""
                    if "?" in path:
                        path, args = path.split("?", 1)
                        args = "?" + args

                    ext = ""
                    if not path.endswith("/"):
                        dirname = os.path.dirname(path)
                        a, b = os.path.splitext(os.path.basename(path))
                        a = a + get_random_str(4)
                        ext = b
                        path_error = "".join([dirname, a, b]) + args
                    else:
                        path_error = path[:-1] + get_random_str(4) + path[-1]
                    # 进行content-type比较
                    if ext in self.exts_bak:
                        if "/html" in r.headers.get("Content-Type"):
                            return False
                    # 进行不同文件名内容相似度比较

                    url_ = self.url[:-1] + path_error
                    logger.debug("test new url:{}".format(url_))
                    req_ = self.parser.generaterequest({"url": url_, "method": "GET"})
                    r_ = request(**req_)
                    if r_ is not None and similar(r_.content, r.content) < self.similar_rate:
                        # 再来一关，根据历史发现的文件返回包的Content-Type,Size比较
                        if self.similar_others(r):
                            return (r.status_code, len(r.content))
            else:
                return r.content
        return False

    def run(self, path):
        try:
            res = self.check_url(path)
            if res is not False:
                status_code, length = res
                if not path.startswith("/"):
                    path = "/" + path
                url = self.url[:-1] + path
                self.result.append({
                    "name": self.name,
                    "url": url,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "status_code": status_code,
                        "length": length
                    }
                })
        except Exception as ex:
            logger.warning("dir scan run error:{}".format(ex))

    def similar_others(self, r):
        ct = r.headers.get("Content-Type", "")
        cl = r.headers.get("Content-Length", "")
        if cl == "":
            cl = len(r.content)
        else:
            cl = int(cl)
        # if cl < 500:
        #     self.found_path.add((ct, cl))
        #     return True
        for ct_, cl_ in self.found_path:
            if ct == ct_:
                if min(cl, cl_) / ((cl + cl_) / 2) > 0.97:  # 值越大，代表两个返回包的长度越接近
                    self.found_path.add((ct, cl))
                    return False
        self.found_path.add((ct, cl))
        return True
