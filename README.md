# myscan

myscan是参考awvs的poc目录架构，pocsuite3、sqlmap等代码框架，以及搜集互联网上大量的poc，由python3开发而成的被动扫描工具。
此项目源自个人开发项目，结合个人对web渗透，常见漏洞原理和检测的代码实现实现，通用poc的搜集，被动扫描器设计，以及信息搜集等思考实践。

## 法律免责声明

未经事先双方同意，使用myscan攻击目标是非法的。  
myscan仅用于安全测试目的

## 运行原理
myscan依赖burpsuite和redis，需启动redis和burpsuite插入myscan的插件。

依靠burp强大的抓包和解析数据包的功能，插件调取api把burp的请求体和响应体的处理数据整合成json数据传输到redis。

myscan调取redis数据，对每一个request/response数据包进行perfile(访问url)、perfolder(每一个目录)、perscheme(每一个数据包)分类去重，通过redis分发到各个子进程与运行相应的poc。

![流程图](docs/images/流程图.png)

## 演示地址

[myscan演示视频](https://www.bilibili.com/video/BV1tV411f7p6/)



## 如何运行

平台要求:

不支持Windows,目前仅支持Linux（Windows python多进程不会把变量共享过去）

软件要求: 

python > 3.7.5 , redis-server ,(开发基于3.7.5，某些版本会出问题)

```bash
$ redis-server # 起一个redis服务，默认监听127.1:6379
$ pip3 install -r requirements.txt 安装依赖
$ # burpsuite安转扩展插件,默认连接127.1:6379
$ python3 cli.py -h 
```

Example:


禁用未授权,baseline，cors，jsonp插件，指定输出:

```
python3 cli.py webscan --disable power baseline cors jsonp --html-output test.html 
```
把redis所有数据清除（即清除当前的所有任务队列），针对指定host，指定redis连接方式,默认输出到myscan_result_{num}.html，启动10个进程，某些poc线程为5

```
python3 cli.py webscan --host 127.0.0.1 192.168 --redis pass@127.0.0.1:6379:0 --clean --process 10 --threads 5
```
启动反连平台(服务器端)

```
python3 cli.py reverse
```

更多参数

```
python cli.py -h
```



## 检测插件

XSS，SQL，XXE，CORS，JSONP，CRLF，CmdInject，敏感信息泄漏，Struts2，Thinkphp，Weblogic... ，详见pocs目录，新的检测模块将不断添加。

## 优势与不足

* 支持反连平台，检测rmi，ldap，http，dnslog简单。
* python代码开源，不会编程难写poc。
* 依靠burp和redis，不用写监听程序和多进程处理数据容易，同时也严重依赖burp。
* 自定义插件，比如把request/response数据包导入到elasticsearch，便于后续查询。
* 通过redis，可分布式检测。

