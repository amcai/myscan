# !/usr/bin/env python3
# @Time    : 2020/7/29
# @Author  : caicai
# @File    : samba_cve_2017-7494.py




from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options, logger
from myscan.lib.hostscan.common import get_data_from_file
from myscan.lib.core.threads import mythread
import os
from smb.SMBConnection import SMBConnection


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "samba_cve_2017-749"
        self.vulmsg = "rce exploit"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["netbios-ssn", "samba"],  # nmap本身识别microsoft-ds ,为了以后扩展自己识别脚本,多个samba
            "type": "tcp"
        }
        # 自定义
        self.right_pwd = None

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        return
        pwdfile = os.path.join("brute", "smb_pass")
        userfile = os.path.join("brute", "smb_user")
        pwds = [""]
        pwds += get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, pwdfile))
        users = get_data_from_file(os.path.join(paths.MYSCAN_DATA_PATH, userfile))
        userpass = []
        for user in users:
            for pwd in pwds:
                userpass.append((user, pwd))
        mythread(self.crack_smb, userpass, cmd_line_options.threads)
        if self.right_pwd is not None:
            self.result.append({
                "name": self.name,
                "url": "tcp://{}:{}".format(self.addr, self.port),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "user/pwd": "/".join(self.right_pwd)
                }
            })

    def crack_smb(self, userpwd):
        user, pwd = userpwd
        if self.right_pwd is None:
            logger.debug("test smb_brute userpwd:{}".format(userpwd))
            conn = SMBConnection(user, pwd, "client", self.addr, use_ntlm_v2=True, is_direct_tcp=True)
            try:
                smb_authentication_successful = conn.connect(self.addr, self.addr, timeout=6)
                if smb_authentication_successful:
                    self.right_pwd = userpwd
                conn.close()
            except Exception as e:
                pass
            finally:
                conn.close()
