## 进阶用法

### burp插件
>burp中一个请求体必须对应的响应体才能导入到redis中。
>
>burp插件具有两种收集数据方式，一种是proxy模式，此模式是代理proxy和repeater两种流量流量，此流量会自动去重。一种是右键模式，此模式在proxy，repeater等其他地方右键出现"Send to Myscan"点击即可把数据包格式化发送到redis，此流量不会去重。当然不要忘了第一句话，必须有响应体才能导入到redis。
>
>以上两种模式，基本覆盖测试需求，如爬虫，或正常浏览页面的流量代理到burp，此时proxy模式打开情况下，流量自动去重，送入redis等待python工程取出来检测。 如果在进行后台测试时，可把proxy模式关闭，流量经过burp后，可选择性右键"Send to Myscan"，当然在Proxy项目头可按住Shift多选发送。

### 反连平台使用
>
>此处等待作者吧啦吧啦
>

### 

### 用户可开发poc目录
* 所有开发均针对下列Example dict数据结构，进行开发，主要可开发三个方面。
* 用户可在plugin目录开发，比如把所有burpsuite过来的数据，不去重保存在elasticsearch，详见plugins/esexport.py
* 用户可在pocs的三个目录perfile，perfolder，perscheme对针对文件，针对路径，针对请求体进行poc开发。
* 用户可在pocs的search.py目录添加search规则进行开发。
* 用户可在config.py配置自己poc脚本里面的开关变量。


### Example dict
```
{
   "filter": false,  #决定是否过滤，burp的proxy传过来为true，右键发过来为false
   "request": {
      "headers": {
         "Origin": "http://www.myscantest.com:8888",
         "Cookie": "PHPSESSID=97k6cpaf7u21ba80vj1osp7q15; security=impossible",
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
         "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36",
         "Referer": "http://www.myscantest.com:8888/login.php",
         "Connection": "close",
         "Host": "www.myscantest.com:8888",
         "Accept-Encoding": "gzip, deflate",
         "Cache-Control": "max-age=0",
         "Upgrade-Insecure-Requests": "1",
         "Accept-Language": "zh-CN,zh;q=0.9",
         "Content-Length": "88",
         "Content-Type": "application/x-www-form-urlencoded"
      },
      "raw_ignore": false,
      "method": "POST",
      "content_type": 1, #{-1: "CONTENT_TYPE_UNKNOWN", 0:"CONTENT_TYPE_NONE",1: "CONTENT_TYPE_URL_ENCODED", 2: "CONTENT_TYPE_MULTIPART", 3: "CONTENT_TYPE_XML", 4: "CONTENT_TYPE_JSON", 5: "CONTENT_TYPE_AMF", } #上传:---2   body:a=haha---1     body:soap---0   body:json---4
      "raw": "UE9TVCAvbG9naW4ucGhwIEhUVFAvMS4xDQpIb3N0OiB3d3cubXlzY2FudGVzdC5jb206ODg4OA0K\nQ29udGVudC1MZW5ndGg6IDg4DQpDYWNoZS1Db250cm9sOiBtYXgtYWdlPTANCk9yaWdpbjogaHR0\ncDovL3d3dy5teXNjYW50ZXN0LmNvbTo4ODg4DQpVcGdyYWRlLUluc2VjdXJlLVJlcXVlc3RzOiAx\nDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZA0KVXNlci1B\nZ2VudDogTW96aWxsYS81LjAgKE1hY2ludG9zaDsgSW50ZWwgTWFjIE9TIFggMTBfMTNfNikgQXBw\nbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzc5LjAuMzk0NS4xMTcg\nU2FmYXJpLzUzNy4zNg0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFw\ncGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS93ZWJwLGltYWdlL2FwbmcsKi8qO3E9MC44LGFwcGxp\nY2F0aW9uL3NpZ25lZC1leGNoYW5nZTt2PWIzO3E9MC45DQpSZWZlcmVyOiBodHRwOi8vd3d3Lm15\nc2NhbnRlc3QuY29tOjg4ODgvbG9naW4ucGhwDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxh\ndGUNCkFjY2VwdC1MYW5ndWFnZTogemgtQ04semg7cT0wLjkNCkNvb2tpZTogUEhQU0VTU0lEPTk3\nazZjcGFmN3UyMWJhODB2ajFvc3A3cTE1OyBzZWN1cml0eT1pbXBvc3NpYmxlDQpDb25uZWN0aW9u\nOiBjbG9zZQ0KDQp1c2VybmFtZT1hZG1pbiZwYXNzd29yZD1wYXNzd29yZCZMb2dpbj1Mb2dpbiZ1\nc2VyX3Rva2VuPTVkNWFlMTQ0NDMyY2Y4ZDJlMGU4NDNiN2NlYjZiYWY5",
      "params": {
         "params_body": [
            {
               "namestart": 695,
               "nameend": 703,
               "valuestart": 704,
               "name": "username",
               "valueend": 709,
               "type": 1,
               "value": "admin"
            },
            {
               "namestart": 710,
               "nameend": 718,
               "valuestart": 719,
               "name": "password",
               "valueend": 727,
               "type": 1,
               "value": "password"
            },
            {
               "namestart": 728,
               "nameend": 733,
               "valuestart": 734,
               "name": "Login",
               "valueend": 739,
               "type": 1,
               "value": "Login"
            },
            {
               "namestart": 740,
               "nameend": 750,
               "valuestart": 751,
               "name": "user_token",
               "valueend": 783,
               "type": 1,
               "value": "5d5ae144432cf8d2e0e843b7ceb6baf9"
            }
         ],
         "params_url": [],
         "params_cookie": [
            {
               "namestart": 615,
               "nameend": 624,
               "valuestart": 625,
               "name": "PHPSESSID",
               "valueend": 651,
               "type": 2,
               "value": "97k6cpaf7u21ba80vj1osp7q15"
            },
            {
               "namestart": 653,
               "nameend": 661,
               "valuestart": 662,
               "name": "security",
               "valueend": 672,
               "type": 2,
               "value": "impossible"
            }
         ]
      },
      "bodyoffset": 695
   },
   "response": {
      "headers": {
         "Server": "Apache/2.4.7 (Ubuntu)",
         "Cache-Control": "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
         "Connection": "close",
         "Expires": "Thu, 19 Nov 1981 08:52:00 GMT",
         "Pragma": "no-cache",
         "Content-Length": "0",
         "Date": "Tue, 04 Feb 2020 08:23:57 GMT",
         "X-Powered-By": "PHP/5.5.9-1ubuntu4.25",
         "Location": "index.php",
         "Content-Type": "text/html"
      },
      "raw_ignore": false,
      "mime_stated": "HTML",
      "raw": "SFRUUC8xLjEgMzAyIEZvdW5kDQpEYXRlOiBUdWUsIDA0IEZlYiAyMDIwIDA4OjIzOjU3IEdNVA0K\nU2VydmVyOiBBcGFjaGUvMi40LjcgKFVidW50dSkNClgtUG93ZXJlZC1CeTogUEhQLzUuNS45LTF1\nYnVudHU0LjI1DQpFeHBpcmVzOiBUaHUsIDE5IE5vdiAxOTgxIDA4OjUyOjAwIEdNVA0KQ2FjaGUt\nQ29udHJvbDogbm8tc3RvcmUsIG5vLWNhY2hlLCBtdXN0LXJldmFsaWRhdGUsIHBvc3QtY2hlY2s9\nMCwgcHJlLWNoZWNrPTANClByYWdtYTogbm8tY2FjaGUNCkxvY2F0aW9uOiBpbmRleC5waHANCkNv\nbnRlbnQtTGVuZ3RoOiAwDQpDb25uZWN0aW9uOiBjbG9zZQ0KQ29udGVudC1UeXBlOiB0ZXh0L2h0\nbWwNCg0K",
      "bodyoffset": 348,
      "status": 302,
      "mime_inferred": ""
   },
   "url": {
      "path": "/login.php",
      "path_folder":"http://www.myscantest.com:8888/",
      "protocol": "http",
      "extension": "php",
      "port": 8888,
      "host": "www.myscantest.com", #不会带端口
      "url": "http://www.myscantest.com:8888/login.php"
   },
   "others": "powered by \u83dc\u83dc"
}
```

### Redis 各个字段及其作用
* burpdata (list) :来自burp格式化json字符串
* workpython (list) :
* count_all (hash) : total:测试总数,queue:len(burp_data)
                    block_host_port:len(block_host_port) 
* vuln_all (list): 存放所有result的python序列化dict
* vuln_(pocname) (list): 存放pocname的result的python序列化dict
* saerch_(hosthash) (set): search 搜索结果的host去重

### POC编写

程序已有多种样例，可先阅读已编写好的代码。
> 在pocs目录，共perfile，perfolder，perscheme三个目录，每个目录下均有__template.py文件，此文件为模版文件，编写poc时，复制一份重命名即可。
> 
> 在POC文件里，类名必须为POC，必须包含一个self.result用来保存结果，和一个verify方法，如模板所示主要编写在verify方法里面pass部分。
> 
> 建议使用内置的requests模块，具有统计失败次数，搜索功能。
> 
> 成功的结果以dict数据保存在list类型self.result里，dict数据需按照如下格式来
> 
> ```
self.result.append({
            "name": self.name,
            "url": "http://example.com/test.php",
            "level": self.level,  # 0:Low  1:Medium 2:High
            "detail": {
                "vulmsg": self.vulmsg,
            }
        })
>```
>dict数据必须包含"name","url","level","detail"四个key,其中detail字典里可自定义数据。
> 
