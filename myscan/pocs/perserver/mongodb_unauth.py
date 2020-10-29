# !/usr/bin/env python3
# @Time    : 2020/7/27
# @Author  : caicai
# @File    : mongodb_unauth.py


from myscan.lib.hostscan.pocbase import PocBase
import pymongo


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "mongodb_unauth"
        self.vulmsg = "unatuh access"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["mongodb"],  # nmap本身识别microsoft-ds ,为了以后扩展自己识别脚本,多个smb
            "type": "tcp"
        }

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        try:
            conn = pymongo.MongoClient(self.addr, self.port, socketTimeoutMS=3000)
            dbname = conn.list_database_names()
            if dbname:
                self.result.append({
                    "name": self.name,
                    "url": "tcp://{}:{}".format(self.addr, self.port),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "dbname": str(dbname)
                    }
                })
        except Exception as e:
            pass
