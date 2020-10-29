此模块待开发...

### Example dict

```
{
  "filter": false, # redis是否去重 
  "scan": false, # 是否再次用nmap确定服务，当为True时，service字段将无效
  "addr": "1.1.1.1", # 支持域名
  "port": 80,  
  "type": "tcp", 
  "service": {  # nmap识别出来服务以及版本
    "smb": "6.1",
    "unknown": ""
  }
}
```


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
>

