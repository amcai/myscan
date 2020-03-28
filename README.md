# myscan

myscan是参考awvs的poc目录架构，pocsuite3、sqlmap等代码框架，以及搜集互联网上大量python开发项目的poc，由python3开发而成的被动扫描工具。
此项目源自个人开发项目，结合个人对web渗透，常见漏洞原理和检测的代码实现实现，通用poc的搜集，被动扫描器设计，以及信息搜集等思考实践。

## 法律免责声明

未经事先双方同意，使用myscan攻击目标是非法的。  
myscan仅用于安全测试目的

## 运行原理
myscan依赖burpsuite和redis，需启动redis和burpsuite插入myscan的插件。

依靠burp强大的抓包和解析数据包的功能，插件调取api把burp的请求体和响应体的处理数据整合成json数据传输到redis。

myscan调取redis数据，对每一个request/response数据包进行perfile(访问url)、perfolder(每一个目录)、perscheme(每一个数据包)分类去重，通过redis分发到各个子进程与运行相应的poc。

## 演示地址

[myscan演示视频](https://www.bilibili.com/video/BV1tV411f7p6/)



## 如何运行

平台要求:

不支持Windows,目前仅支持Linux（Windows python的坑爹之处，多进程不把变量共享过去）

软件要求: 

python > 3.7.5 , redis-server ,(开发基于3.7.5，高版本未测试)

```bash
$ redis-server # 起一个redis服务，默认监听127.1:6379
$ pip3 install -r requirements.txt 安装依赖
$ # burpsuite安转扩展插件,默认连接127.1:6379
$ python3 cli.py -h 
```

Example:


禁用越权插件（未授权插件，不禁用很多垃圾告警），指定输出:

```
python3 cli.py webscan --disable power --html-output test.html
```
把redis所有数据清除，针对指定host，指定redis连接方式,默认输出到myscan_result.html

```
python3 cli.py webscan --host 127.0.0.1 --redis pass@127.0.0.1:6379:0 --clean
```
启动反连平台(服务器端)

```
python3 cli.py reverse
```

## 检测插件

- PerFile (每个文件 )
    - [x] crlf注入
    - [x] bash_cve-2014-6271
- PerFolder (每个目录)
    - [x] 敏感文件扫描
    - [x] iis_cve-2017-7269
    - [x] iis_短文件名
    - [x] phpstudy_backdoor
    - [x] tomcat_cve-2017-12615
- PerScheme (每个数据包)
    - [x] 命令注入
    - [x] cors跨域
    - [x] host头注入
    - [x] jsonp
    - [x] php代码注入
    - [x] php路径泄漏
    - [x] 未授权访问
    - [x] URL跳转
    - [x] sql报错注入
    - [x] sql布尔盲注
    - [x] ssrf(需配置反连)
    - [x] xss
    - [x] xxe(部分需配置反连)
    - [x] 探测webdav
    - [x] fastjson_rce(需配置反连)
- Serarch (搜索模式)
    - [x] 目录泄露

## 优势与不足

* python代码开源，不会编程难写poc。
* 依靠burp和redis，不用写监听程序和多进程处理数据容易。
* 自定义插件，比如把request/response数据包导入到elasticsearch，便于后续查询。
* 通过redis，可分布式检测。
