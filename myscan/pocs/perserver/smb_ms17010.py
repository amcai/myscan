# !/usr/bin/env python3
# @Time    : 2020/7/27
# @Author  : caicai
# @File    : smb_ms17010.py


from myscan.lib.hostscan.pocbase import PocBase
import socket
import binascii


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "smb_ms17010"
        self.vulmsg = "rce . referer:http://bobao.360.cn/learning/detail/3738.html"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["microsoft-ds", "smb"],  # nmap本身识别microsoft-ds ,为了以后扩展自己识别脚本,多个smb
            "type": "tcp"
        }
        # 自定义参数

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        negotiate_protocol_request = binascii.unhexlify(
            "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify(
            "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((self.addr, self.port))
            s.send(negotiate_protocol_request)
            s.recv(1024)
            s.send(session_setup_request)
            data = s.recv(1024)
            user_id = data[32:34]
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % (
                (58 + len(self.addr)), binascii.b2a_hex(user_id).decode(),
                binascii.b2a_hex(self.addr.encode()).decode())
            s.send(binascii.unhexlify(tree_connect_andx_request))
            data = s.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % binascii.b2a_hex(
                allid).decode()
            s.send(binascii.unhexlify(payload))
            data = s.recv(1024)
            s.close()
            if b"\x05\x02\x00\xc0" in data:
                self.result.append({
                    "name": self.name,
                    "url": "tcp://{}:{}".format(self.addr, self.port),
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                    }
                })

            s.close()
        except Exception as ex:
            pass