![myscan](https://socialify.git.ci/amcai/myscan/image?description=1&font=Raleway&forks=1&issues=1&language=1&owner=1&pattern=Signal&stargazers=1&theme=Light)

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

XSS，SQL，XXE，CORS，JSONP，CRLF，CmdInject，敏感信息泄漏，Struts2，Thinkphp，Weblogic... ，详见pocs目录，可根据数据包的特征，对每个参数进行测试，或者选择性测试，新的检测模块将不断添加。

支持检测POC如下：

```shell
.
├── perfile
│   ├── myscan_crlf.py
│   ├── myscan_dns_zone_transfer.py
│   ├── myscan_getpage.py
│   ├── myscan_webpack_leak.py
│   ├── poc_bash-cve-2014-6271.py
│   ├── poc_rails_cve-2019-5418_2019.py
│   ├── poc_struts2-057.py
│   ├── poc_struts2_016.py
│   ├── poc_struts2_032.py
│   └── poc_struts2_dev.py
├── perfolder
│   ├── apache
│   │   ├── poc_apache-flink-upload-rce_2020.py
│   │   ├── poc_apache-ofbiz-cve-2018-8033-xxe_2018.py
│   │   └── poc_apache-ofbiz-cve-2020-9496-xml-deserialization_2020.py
│   ├── axis
│   │   └── poc_axis_cve-2019-0227_2019.py
│   ├── baota
│   │   └── poc_baota_pmaunauth_2020.py
│   ├── basework
│   │   └── myscan_getpage.py
│   ├── bullwark
│   │   └── poc_bullwark-momentum-lfi_2019.py
│   ├── cacti
│   │   └── poc_cacti-weathermap-file-write_2019.py
│   ├── cisco
│   │   └── poc_cisco_asa_cve-2020-3452.py
│   ├── citrix
│   │   ├── poc_citrix-cve-2019-19781-path-traversal_2019.py
│   │   ├── poc_citrix-cve-2020-8191-xss_2020.py
│   │   └── poc_citrix-cve-2020-8193-unauthorized.py
│   ├── coldfusion
│   │   └── poc_coldfusion-cve-2010-2861-lfi_2010.py
│   ├── confluence
│   │   └── poc_confluence-cve-2019-3396-lfi_2019.py
│   ├── consul
│   │   └── poc_consul-rce_2020.py
│   ├── coremail
│   │   └── poc_coremail-cnvd-2019-16798_2019.py
│   ├── couchcms
│   │   └── poc_couchcms-cve-2018-7662_2018.py
│   ├── couchdb
│   │   ├── poc_couchdb-cve-2017-12635_2017.py
│   │   └── poc_couchdb-unauth_2016.py
│   ├── discuz
│   │   ├── poc_discuz-v72-sqli_2018.py
│   │   ├── poc_discuz-wechat-plugins-unauth_2016.py
│   │   └── poc_discuz-wooyun-2010-080723_2010.py
│   ├── dlink
│   │   ├── poc_dlink-850l-info-leak_2018.py
│   │   ├── poc_dlink-cve-2019-16920-rce_2019.py
│   │   └── poc_dlink-cve-2019-17506_2019.py
│   ├── docker
│   │   ├── poc_docker-api-unauthorized-rce_2017.py
│   │   └── poc_docker-registry-api-unauth_2017.py
│   ├── druid
│   │   └── poc_druid-monitor-unauth_2019.py
│   ├── drupal
│   │   └── poc_drupal-cve-2019-6340_2019.py
│   ├── ecology
│   │   ├── poc_ecology-filedownload-directory-traversal_2018.py
│   │   ├── poc_ecology-javabeanshell-rce_2019.py
│   │   ├── poc_ecology-springframework-directory-traversal_2019.py
│   │   ├── poc_ecology-syncuserinfo-sqli_2019.py
│   │   ├── poc_ecology-validate-sqli_2019.py
│   │   ├── poc_ecology-workflowcentertreedata-sqli_2019.py
│   │   └── poc_ecology_db_leak_2020.py
│   ├── ecshop
│   │   └── poc_ecshop-360-rce_2019.py
│   ├── elasticsearch
│   │   ├── poc_elasticsearch-cve-2014-3120_2014.py
│   │   ├── poc_elasticsearch-cve-2015-1427_2015.py
│   │   ├── poc_elasticsearch-cve-2015-3337-lfi_2015.py
│   │   └── poc_elasticsearch-unauth.py
│   ├── f5
│   │   └── poc_f5-tmui-cve-2020-5902-rce_2020.py
│   ├── finecms
│   │   └── poc_finecms-sqli_2019.py
│   ├── finereport
│   │   └── poc_finereport-directory-traversal_2019.py
│   ├── hadoop
│   │   └── poc_hadoop_unauth_acc_2018.py
│   ├── hikvision
│   │   └── poc_hikvision_xss_2020.py
│   ├── iis
│   │   ├── poc_iis_6.0_cve-2017-7269.py
│   │   └── poc_iis_6.0_shortname.py
│   ├── info
│   │   ├── myscan_baseline.py
│   │   ├── myscan_dirscan.py
│   │   ├── myscan_put_upload.py
│   │   ├── myscan_sensitive_file_leak.py
│   │   ├── poc_docker_registry_listing_2019.py
│   │   ├── poc_front-page-misconfig.py
│   │   ├── poc_jira_service-desk-signup.py
│   │   ├── poc_jira_unauthenticated-projects.py
│   │   ├── poc_springboot-actuators.py
│   │   └── poc_webeditor_found.py
│   ├── jboss
│   │   └── poc_jboss_found_2020.py
│   ├── jira
│   │   ├── poc_jira-cve-2019-11581_2019.py
│   │   ├── poc_jira-ssrf-cve-2019-8451_2019.py
│   │   └── poc_jira_userenum_cve-2020-14181_2020.py
│   ├── jolokia
│   │   └── poc_jolokia_CVE-2018-1000130_2018.py
│   ├── joomla
│   │   ├── poc_joomla-cnvd-2019-34135-rce_2019.py
│   │   └── poc_joomla-cve-2017-8917-sqli_2017.py
│   ├── kibana
│   │   └── poc_kibana-unauth_2018.py
│   ├── kong
│   │   └── poc_kong-cve-2020-11710-unauth_2020.py
│   ├── kylin
│   │   └── poc_kylin_cve-2020-13937_2020.py
│   ├── laravel
│   │   └── poc_laravel-debug-info-leak_2020.py
│   ├── myscan_redirect.py
│   ├── myscan_swf_xss.py
│   ├── nexus
│   │   ├── poc_nexus-cve-2019-7238_2019.py
│   │   └── poc_nexus-default-password_2020.py
│   ├── nginx
│   │   └── poc_nginx-module-vts-xss.py
│   ├── nsfocus
│   ├── oracle
│   │   └── oracle_ebs-bispgrapgh-file-read_2020.py
│   ├── phpstudy
│   │   ├── poc_phpstudy-nginx-wrong-resolve_2020.py
│   │   └── poc_phpstudy_backdoor_2019.py
│   ├── poc_user-agent-shell-shock_2018.py
│   ├── qnap
│   │   └── poc_qnap-cve-2019-7192_2019.py
│   ├── rails
│   │   └── poc_rails-cve-2018-3760_2018.py
│   ├── sangfor
│   │   ├── poc_sangfor_edr_rce_2020.py
│   │   ├── poc_sangfor_edr_rce_202009_2020.py
│   │   ├── poc_sangfor_edr_unauth_2020.py
│   │   └── poc_sangfor_rce_2020.py
│   ├── sap
│   │   └── poc_sap_cve-2020-6287_2020.py
│   ├── seeyon
│   │   ├── poc_seeyon_fileread_2020.py
│   │   └── poc_seeyon_u8_sqli_2020.py
│   ├── solr
│   │   ├── poc_solr-velocity-template-rce_2019.py
│   │   ├── poc_solr_cve-2017-12629-xxe_2017.py
│   │   └── poc_solr_cve-2019-0193_2019.py
│   ├── sonarqube
│   │   └── poc_sonarqube_api_access.py
│   ├── spark
│   │   └── poc_spark_unacc_2018.py
│   ├── spring
│   │   ├── poc_spring-cloud-cve-2020-5410_2020.py
│   │   ├── poc_spring_cloud-cve-2020-5405_2020.py
│   │   ├── poc_spring_cve-2016-4977_2016.py
│   │   ├── poc_spring_cve-2019-3799_2019.py
│   │   ├── poc_spring_xss_2020.py
│   │   ├── poc_springboot-actuators-jolokia-xxe.py
│   │   └── poc_springboot_h2_db_rce_2020.py
│   ├── struts
│   │   ├── poc_struts2_033.py
│   │   ├── poc_struts2_037.py
│   │   ├── poc_struts2_045.py
│   │   ├── poc_struts2_046.py
│   │   └── poc_struts2_052.py
│   ├── supervisord
│   │   └── poc_supervisord-cve-2017-11610_2017.py
│   ├── symantec
│   │   └── poc_symantec-messaging-gateway_lfi_2020.py
│   ├── thinkadmin
│   │   └── poc_thinkadmin_unauth_and_read_file.py
│   ├── thinkcmf
│   │   ├── poc_thinkcmf-lfi_2020.py
│   │   └── poc_thinkcmf_rce_2019.py
│   ├── thinkphp
│   │   └── poc_thinkphp_rce_all_2020.py
│   ├── tomcat
│   │   ├── poc_tomcat-manager-pathnormalization.py
│   │   ├── poc_tomcat_cve-2017-12615_2017.py
│   │   └── poc_tomcat_cve-2018-11759_2018.py
│   ├── tongda
│   │   ├── poc_tongda_oa_rce1_2020.py
│   │   └── poc_tongda_oa_rce_2020.py
│   ├── vmware
│   │   ├── poc_spring-cloud-netflix-hystrix-dashboard_CVE-2020-5412_2020.py
│   │   └── poc_vmware_vcenter_readfile_2020.py
│   ├── weaver
│   │   └── poc_weaver-ebridge-file-read_2020.py
│   ├── weblogic
│   │   ├── poc_weblogic_cve-2017-10271_2017.py
│   │   ├── poc_weblogic_cve-2019-2725_v10_2019.py
│   │   ├── poc_weblogic_cve-2019-2725_v12_2019.py
│   │   ├── poc_weblogic_cve-2019-2729_1_2019.py
│   │   ├── poc_weblogic_cve-2019-2729_2_2019.py
│   │   ├── poc_weblogic_cve-2020-14882_2020.py
│   │   └── poc_weblogic_ssrf_2018.py
│   ├── wordpress
│   │   ├── poc_wordpress-duplicator-path-traversal.py
│   │   ├── poc_wordpress_configfile.py
│   │   └── poc_wordpress_wordfence_xss.py
│   ├── youphptube
│   │   └── poc_youphptube-encoder-cve-2019-5129_2019.py
│   └── zabbix
│       ├── poc_zabbix_authentication-bypass_2016.py
│       └── poc_zabbix_cve-2016-10134_2016.py
├── perscheme
│   ├── info
│   │   ├── myscan_baseline.py
│   │   └── myscan_sensitive_msg_transfer.py
│   ├── myscan_cmd_inject.py
│   ├── myscan_cors.py
│   ├── myscan_host_inject.py
│   ├── myscan_jsonp.py
│   ├── myscan_phpcode_inject.py
│   ├── myscan_phppath_leak.py
│   ├── myscan_power_unauth.py
│   ├── myscan_redirect.py
│   ├── myscan_sqli_error.py
│   ├── myscan_sqli_timeblind.py
│   ├── myscan_ssrf.py
│   ├── myscan_ssti.py
│   ├── myscan_xss.py
│   ├── myscan_xxe.py
│   ├── others_fastjson_dnslog_found.py
│   ├── others_jackson_fastjson_error_found.py
│   ├── others_webdav.py
│   ├── poc_fastjson_deserialization_rce_2020.py
│   ├── poc_shiro_rce_2019.py
│   ├── poc_struts2-053.py
│   ├── poc_struts2_029.py
│   ├── poc_struts2_048.py
│   └── tomcat
│       └── poc_tomcat-manager-pathnormalization_verify_2020.py
├── perserver
│   ├── mongodb_unauth.py
│   ├── mssql_brute.py
│   ├── mysql_brute.py
│   ├── redis_brute.py
│   ├── rmi_deserialization.py
│   ├── samba_cve_2017-7494.py
│   ├── smb_brute.py
│   ├── smb_info.py
│   ├── smb_ms17010.py
│   ├── weblogic_cve_2020_14645.py
│   ├── weblogic_cve_2020_2555.py
│   └── weblogic_cve_2020_2883.py
└── search.py
```




## 优势与不足

* 支持反连平台，检测rmi，ldap，http，dnslog简单。
* python代码开源，不会编程难写poc。
* 依靠burp和redis，不用写监听程序和多进程处理数据容易，同时也严重依赖burp。
* 自定义插件，比如把request/response数据包导入到elasticsearch，便于后续查询。
* 通过redis，可分布式检测。

