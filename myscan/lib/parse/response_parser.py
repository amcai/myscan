# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : response_parser.py
class response_parser():
    '''
    此类解析处理rqeuests返回的的respose类
    '''
    def __init__(self, r):
        self.data = r

    def getrequestraw(self):
        '''
        return bytes[]
        '''
        request_raw = "{} {} HTTP/1.1\r\n".format(self.data.request.method, self.data.request.path_url).encode()
        for k, v in self.data.request.headers.items():
            request_raw += "{}: {}\r\n".format(k, v).encode()
        request_raw += b"\r\n"
        if self.data.request.body:
            if isinstance(self.data.request.body,str):
                request_raw += self.data.request.body.encode(errors="ignore")
            else:
                request_raw += self.data.request.body
        return request_raw

    def getresponseraw(self):
        '''
        return bytes[]
        '''
        response_raw = "HTTP/1.1 {} {}\r\n".format(self.data.status_code, self.data.reason).encode()
        for k, v in self.data.headers.items():
            response_raw += "{}: {}\r\n".format(k, v).encode()
        response_raw += b"\r\n"
        response_raw += self.data.content
        return response_raw

    def geturl(self):
        return self.data.url.split("?")[0]
