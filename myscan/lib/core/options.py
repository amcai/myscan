#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : options.py
import copy
from myscan.lib.core.data import cmd_line_options, logger, paths, others
import logging
import os
import sys
from myscan.lib.parse.cmd_line_parser import cmd_line_parser
from myscan.lib.core.common import banner
from myscan.lib.core.common_reverse import check_reverse
from myscan.lib.core.register import load_file_to_module
from myscan.lib.scriptlib.ssti.importssti import importssti
from myscan.config import plugin_set, db_set
from myscan.lib.core.conn import set_es_conn
from myscan.lib.patch.paramiko_patch import patch_banner_timeout
from myscan.lib.patch.ipv6_patch import ipv6_patch
from myscan.lib.core.dns import find_dns_server


def init_options():
    cmd_line_options.update(cmd_line_parser().__dict__)
    # 判断banner
    if cmd_line_options.show_version:
        print(banner())
        sys.exit()
    print(banner())
    # 判断check-reveres
    if cmd_line_options.check_reverse:
        check_reverse()
        sys.exit()
    if cmd_line_options.command == "reverse":
        return
    # 此处需要改进，添加判读，容错，和sock代理等
    if cmd_line_options.proxy:
        host_port = cmd_line_options.proxy
        cmd_line_options.proxy = {"http": "http://{}".format(host_port),
                                  "https": "https://{}".format(host_port),
                                  }
    else:
        cmd_line_options.proxy = {}
    if cmd_line_options.verbose == 0:
        logger.logger.setLevel(logging.DEBUG)
    elif cmd_line_options.verbose == 1:
        logger.logger.setLevel(logging.INFO)
    elif cmd_line_options.verbose == 2:
        logger.logger.setLevel(logging.WARNING)
    elif cmd_line_options.verbose == 3:
        logger.logger.setLevel(logging.CRITICAL)

    # 验证DNS_Servers，添加到全局变量
    if db_set.get("es_open"):
        servers = find_dns_server().find_dnsservers()
        logger.info("Found dns_servers:{}".format(servers))
        if servers == []:
            logger.warning("Not Found dns_servers, Check your Networks or edit data/common/dns_servers.txt")
            sys.exit()
        others.dns_servers = servers
    # 处理html-output
    logger.info("Vuln results will output to: {}".format(cmd_line_options.html_output))

    cmd_line_options.allow_poc = []
    cmd_line_options.allow_plugin = {}
    cmd_line_options.pocs_perfile = []
    cmd_line_options.pocs_perfoler = []
    cmd_line_options.pocs_perscheme = []
    cmd_line_options.pocs_perserver = []
    cmd_line_options.pocs_load_moudle = {
        "perfile": {},
        "perfolder": {},
        "perscheme": {},
        "perserver": {}
    }
    poc_keys = {
        "perfile": cmd_line_options.pocs_perfile,
        "perfolder": cmd_line_options.pocs_perfoler,
        "perscheme": cmd_line_options.pocs_perscheme,
        "perserver": cmd_line_options.pocs_perserver
    }
    if cmd_line_options.command == "webscan":
        cmd_line_options.poc_folders = ["perfile", "perfolder", "perscheme"]
    if cmd_line_options.command == "hostscan":
        cmd_line_options.poc_folders = ["perserver"]
    if "all" not in cmd_line_options.disable:
        if cmd_line_options.disable:
            cmd_line_options.enable = None
            for _dir in cmd_line_options.poc_folders:
                # old way
                # path_dir = os.path.join(paths.MYSCAN_POCS_PATH, _dir)
                # exists_poc_with_ext = list(
                #     filter(lambda x: not x.startswith("__"), os.listdir(path_dir)))
                # temp = copy.deepcopy(exists_poc_with_ext)
                # for disable in cmd_line_options.disable:
                #     for poc in exists_poc_with_ext:
                #         if disable in poc and poc in temp:
                #             temp.remove(poc)
                # for x in temp:
                #     poc_keys.get(_dir).append(os.path.join(path_dir, x))

                # new way to get subdir
                for root, dirs, files in os.walk(os.path.join(paths.MYSCAN_POCS_PATH, _dir)):
                    for file in files:
                        if file.endswith(".py") and not file.startswith("__"):
                            if not any([disable in file for disable in cmd_line_options.disable]):
                                poc_keys.get(_dir).append(os.path.abspath(os.path.join(root, file)))
        else:
            for _dir in cmd_line_options.poc_folders:
                # path_dir = os.path.join(paths.MYSCAN_POCS_PATH, _dir)
                # exists_poc_with_ext = list(
                #     filter(lambda x: (not x.startswith("__") and x.endswith(".py")),
                #            os.listdir(path_dir)))
                # if "*" == cmd_line_options.enable:
                #     for poc in exists_poc_with_ext:
                #         poc_keys.get(_dir).append(os.path.join(path_dir, poc))
                # else:
                #     for disable in cmd_line_options.enable:
                #         for poc in exists_poc_with_ext:
                #             if disable in poc:
                #                 poc_keys.get(_dir).append(os.path.join(path_dir, poc))
                for root, dirs, files in os.walk(os.path.join(paths.MYSCAN_POCS_PATH, _dir)):
                    for file in files:
                        if file.endswith(".py") and not file.startswith("__"):
                            if not cmd_line_options.enable:
                                poc_keys.get(_dir).append(os.path.abspath(os.path.join(root, file)))
                            else:
                                if any([enable in file for enable in cmd_line_options.enable]):
                                    poc_keys.get(_dir).append(os.path.abspath(os.path.join(root, file)))
                                #
                                # for enable in cmd_line_options.enable:
                                #     if enable in file:
                                #         poc_keys.get(_dir).append(os.path.abspath(os.path.join(root, file)))

        for _dir in cmd_line_options.poc_folders:
            logger.debug("{} total: {} pocs".format(_dir.capitalize(), len(list(set(poc_keys.get(_dir))))))
            for poc in list(set(poc_keys.get(_dir))):
                logger.info("Load Pocs:{}".format(poc))
                cmd_line_options.pocs_load_moudle[_dir][hash(poc)] = {
                    "poc": poc,
                    "class": load_file_to_module(poc)
                }
        if cmd_line_options.command == "webscan":
            if not (cmd_line_options.pocs_perfile or cmd_line_options.pocs_perfoler or cmd_line_options.pocs_perscheme):
                logger.warning("No Pocs ,please use  --enable un_auth sqli")
                sys.exit()
        if cmd_line_options.command == "hostscan":
            if not cmd_line_options.pocs_perserver:
                logger.warning("No Pocs ,please use  --enable brute ms17010")
                sys.exit()
    else:
        logger.warning("No Pocs Load!")

    # languages 插件参数处理
    plugins_dir = os.path.join(paths.MYSCAN_PLUGINS_PATH, cmd_line_options.command)
    exists_poc_with_ext = list(
        filter(lambda x: not x.startswith("__"), os.listdir(plugins_dir)))
    if cmd_line_options.plugins:

        for openplugin in list(set(cmd_line_options.plugins)):
            for plugin in exists_poc_with_ext:
                if openplugin in plugin:
                    plugin_path = os.path.join(plugins_dir, plugin)
                    logger.info("Load Plugin:{}".format(plugin_path))
                    cmd_line_options.allow_plugin[hash(plugin_path)] = {
                        "poc": plugin_path,
                        "class": load_file_to_module(plugin_path)
                    }
        if len(cmd_line_options.allow_plugin) == 0:
            logger.warning("No Plugins Load!")
    total_poc = 0
    for x in cmd_line_options.pocs_load_moudle.values():
        total_poc += len(x)
    others.total_pocs=total_poc
    if total_poc == 0 and len(cmd_line_options.allow_plugin) == 0:
        logger.warning("No Plugins Pocs Load! Check your arguments ,Program will exit")
        sys.exit()
    # 处理ssti全局变量
    importssti()

    # 需要注册一下需要urlpath的插件
    poc1 = os.path.join(paths.MYSCAN_POCS_PATH, "perfolder", "info", "myscan_dirscan.py")
    if poc1 in cmd_line_options.pocs_perfoler:
        get_dict()

    # 打补丁
    # patch_banner_timeout() #好像没用
    ipv6_patch()

    # 配置连接

    set_es_conn()

    # 配置dishost host
    if cmd_line_options.host:
        cmd_line_options.dishost = []


def get_dict():
    others.url_dict_path = []
    if plugin_set.get("dirscan").get("dirfile"):
        filename = plugin_set.get("dirscan").get("dirfile")
    else:
        filename = os.path.join(paths.MYSCAN_DATA_PATH, "dir", "dicc.txt")
    try:
        with open(filename) as f:
            for line in f:
                line_ = line.strip()
                if line_:
                    others.url_dict_path.append(line_)
    except Exception as ex:
        logger.warning("dirscan can't open file:{} , get error:{}".format(filename, ex))
    return others.url_dict_path


def gethtmlheader():
    return '''<!DOCTYPE html>
<html>
<head>
    <title>Myscan Report</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <style>
        body {
            margin: 0;
            font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        }

        a {
            text-decoration: none;
        }

        .navbar {
            background-color: #0b77df;
            position: fixed;
            top: 0;
            width: 100%;
            height: 60px;
        }

        #logo {
            margin: 20px 0px 20px 20px;
        }

        .table {
            margin-top: 70px;
            padding: 10px 20px 10px 20px;
        }

        #table {
            border-collapse: collapse;
            width: 100%;
            table-layout: fixed;
            word-break: break-all
        }

        #table td, #table th {
            border: 1px solid #ddd;
            padding: 4px;
        }

        #table tr.table-item:hover {
            background-color: #ddd;
        }

        #table tr.table-item {
            cursor: pointer;
        }

        #table th {
            padding-top: 8px;
            padding-bottom: 8px;
            border: 1px solid #eee;
            background-color: #ddd;
            color: black;
            text-align: left;
        }

        .detail-item {
            margin: 5px;
        }

        [class^="table-detail-"] {
            display: none;
        }

        pre {
            margin: 1px;
        }

        .footer {
            padding: 10px 20px 10px 20px;
        }

        .feedback {
            font-size: 80%;
        }

        .modal {
            display: none; /* Hidden by default */
            position: fixed; /* Stay in place */
            z-index: 1; /* Sit on top */
            padding-top: 100px; /* Location of the box */
            left: 0;
            top: 0;
            width: 100%; /* Full width */
            height: 100%; /* Full height */
            overflow: auto; /* Enable scroll if needed */
            background-color: rgb(0, 0, 0); /* Fallback color */
            background-color: rgba(0, 0, 0, 0.4); /* Black w/ opacity */
        }

        .modal-content {
            background-color: #fefefe;
            margin: auto;
            padding: 20px 20px 70px 20px;
            border: 1px solid #888;
            width: 50%;
        }

        .button {
            border: none;
            color: white;
            padding: 10px 15px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
        }

        .feedback-submit-btn {
            background-color: #4CAF50;
            float: right;
        }

        .feedback-cancel-btn {
            background-color: darkgray;
            float: right;
        }

        #feedback-comment {
            width: 100%;
            border: 1px solid black;
        }

    </style>
    <link href="htmllib/prism.min.css" rel="stylesheet">
    <script src="htmllib/prism.min.js" data-manual></script>
    <script src="htmllib/prism-http.min.js"></script>
    <script src="htmllib/prism-javascript.min.js"></script>
    <style>
        pre[class*="language-"] {
            padding: .5em;
            margin: .5em 0;
            overflow: auto;
            max-height: 300px;
        }

        pre[class*="language-"] {
            background: white;
        }
    </style>
</head>
<body>
<div class="navbar">
    
</div>
<div class="table" id="table-data">
</div>

<script>
    vulnList = [];


    function escapeHtml (unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function toggleDetails (i) {
        let el = document.getElementsByClassName(`table-detail-${i}`);
        let display = "table-row";
        if (vulnList[i].show) {
            display = 'none'
        }
        vulnList[i].show = !vulnList[i].show;
        for (let i = 0; i < el.length; i++) {
            el[i].style.display = display
        }
    }


    

    function b64DecodeUnicode (str) {
        return decodeURIComponent(atob(str).split('').map(function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    }

    
    var jsonObjectIsEmpty = function(jsonObject){
        var isEmpty = true;
        for (var prop in jsonObject){
            isEmpty = false;
            break;
        }
        return isEmpty;
    }
    function getShowContent (k,v) {
        // method 1
        //if(k.toLowerCase() == "request" || k.toLowerCase() =="response"){
        if(k.toLowerCase().search("request") != -1 || k.toLowerCase().search("response") !=-1 ){

            return `<pre class="request-pre"><code class="language-http">${escapeHtml(v)}</code></pre>`;
        }else{
            return `<code>${escapeHtml(v)}</code>`;
        }
        //method2
        // return `<pre class=" language-http"><code class=" language-http">${v}</code></pre>`;
    }

    function generateReport () {
        let vulnDataElements = document.getElementsByClassName("data-vuln-item");
        for (let i = 0; i < vulnDataElements.length; i++) {
            vulnList.push(JSON.parse(b64DecodeUnicode(vulnDataElements[i].value)))
        }


        let tableContent = `<table id="table">
                            <tr><th colspan="1">#</th>
                                <th colspan="1">Level</th>
                                <th colspan="2">Name</th>
                                <th colspan="6">Url</th>
                                <th colspan="2">CreateTime</th>
                            </tr>`;
        for (let i = 0; i < vulnList.length; i++) {
            vulnList[i].show = false;
            tableContent += `
            <tr class="table-item" onclick="toggleDetails(${i})">
                <td colspan="1">#${i + 1}</td>
                <td colspan="1">${vulnList[i].level}</td>
                <td colspan="2">${vulnList[i].name}</td>
                <td colspan="6">
                    <a href="${escapeHtml(vulnList[i].url)}" target="_blank">${escapeHtml(vulnList[i].url)}</a>
                </td>
                <td colspan="2">${vulnList[i].create_time}</td>
            </tr>`;
            if(!jsonObjectIsEmpty(vulnList[i].detail)){

                for(var k in vulnList[i].detail){

                    tableContent += `
                <tr class="table-detail-${i}">
                    <td colspan="2">
                        <p class="detail-item">${k}</p>
                    </td>
                    <td colspan="10">
                        <p class="detail-item">${getShowContent(k,vulnList[i].detail[k])}</p>
                    </td>
                </tr>
                `;

                }
            }
            
        }
        document.getElementById("table-data").innerHTML = tableContent
        try {
            for (let el of document.getElementsByClassName("request-pre")) {
                Prism.highlightElement(el.firstChild, false, null)
            }
        } catch (e) {
            console.log(e)
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', generateReport);
    } else {
        try {
            generateReport()
        } catch (e) {
            alert("报告生成失败")
        }
    }
</script>
<script src="htmllib/raven.min.js" crossorigin="anonymous"></script>


<div id="vuln-records">'''
