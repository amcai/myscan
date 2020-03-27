#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : options.py
import copy
from myscan.lib.core.data import cmd_line_options, logger, paths
import logging
import os
import sys
from myscan.lib.parse.cmd_line_parser import cmd_line_parser
from urllib import parse
from myscan.lib.core.common import banner
from myscan.lib.core.common_reverse import check_reverse
from myscan.lib.core.register import load_file_to_module


def init_options():
    cmd_line_options.update(cmd_line_parser().__dict__)
    # 判断banner
    if cmd_line_options.show_version:
        print(banner())
        sys.exit()
    print(banner())
    #判断check-reveres
    if cmd_line_options.check_reverse:
        check_reverse()
        sys.exit()
    # 此处需要改进，添加判读，容错，和sock代理等
    if cmd_line_options.proxy:
        host_port = cmd_line_options.proxy
        cmd_line_options.proxy = {"http": "http://" + host_port,
                                  "https": "https://" + host_port,
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

    # 处理html-output
    if cmd_line_options.command == "webscan":
        logger.info("Vuln results will output to: {}".format(cmd_line_options.html_output))

        # if os.path.exists(cmd_line_options.html_output):
        #     logger.warning(
        #         "file {} already exists, please backup and remove it at first".format(cmd_line_options.html_output))
        #     sys.exit()
        # else:
        #     try:
        #         with open(cmd_line_options.html_output, "w") as f:
        #             f.write(gethtmlheader())
        #     except Exception as ex:
        #         logger.warning("Create file {} get error:{}".format(cmd_line_options.html_output, ex))
        #         sys.exit()

        cmd_line_options.allow_poc = []
        cmd_line_options.pocs_perfile = []
        cmd_line_options.pocs_perfoler = []
        cmd_line_options.pocs_perscheme = []
        cmd_line_options.pocs_load_moudle={
            "perfile": [],
            "perfolder": [],
            "perscheme": []
        }
        print(cmd_line_options.disable)
        if "all" not in cmd_line_options.disable:
            poc_keys = {
                "perfile": cmd_line_options.pocs_perfile,
                "perfolder": cmd_line_options.pocs_perfoler,
                "perscheme": cmd_line_options.pocs_perscheme
            }

            if cmd_line_options.disable:
                cmd_line_options.enable = None
                for _dir in ["perfile", "perfolder", "perscheme"]:
                    path_dir = os.path.join(paths.MYSCAN_POCS_PATH, _dir)
                    exists_poc_with_ext = list(
                        filter(lambda x: not x.startswith("__"), os.listdir(path_dir)))
                    temp = copy.deepcopy(exists_poc_with_ext)
                    for disable in cmd_line_options.disable:
                        for poc in exists_poc_with_ext:
                            if disable in poc and poc in temp:
                                temp.remove(poc)
                    for x in temp:
                        poc_keys.get(_dir).append(os.path.join(path_dir, x))

            if cmd_line_options.enable:
                for _dir in ["perfile", "perfolder", "perscheme"]:
                    path_dir = os.path.join(paths.MYSCAN_POCS_PATH, _dir)
                    exists_poc_with_ext = list(
                        filter(lambda x: (not x.startswith("__") and (x.endswith(".py") or x.endswith(".yaml"))),
                               os.listdir(path_dir)))
                    if "*" == cmd_line_options.enable:
                        for poc in exists_poc_with_ext:
                            poc_keys.get(_dir).append(os.path.join(path_dir, poc))
                    else:
                        for disable in cmd_line_options.enable:
                            for poc in exists_poc_with_ext:
                                if disable in poc:
                                    poc_keys.get(_dir).append(os.path.join(path_dir, poc))
            for _dir in ["perfile", "perfolder", "perscheme"]:
                logger.debug("{} total: {} pocs".format(_dir.capitalize(), len(poc_keys.get(_dir))))
                for poc in poc_keys.get(_dir):
                    logger.info("Load Pocs:{}".format(poc))
                    cmd_line_options.pocs_load_moudle[_dir].append(
                        {
                            "poc":poc,
                            "class":load_file_to_module(poc)
                        }
                    )


            if not (cmd_line_options.pocs_perfile or cmd_line_options.pocs_perfoler or cmd_line_options.pocs_perscheme):
                logger.warning("No Pocs ,please use --enable * or like --enable un_auth sqli")
                sys.exit()

        # plugin 插件参数处理
        cmd_line_options.open_lugins = []
        plugins_dir = paths.MYSCAN_PLUGINS_PATH
        exists_poc_with_ext = list(
            filter(lambda x: not x.startswith("__"), os.listdir(plugins_dir)))
        if cmd_line_options.plugins:
            for openplugin in list(set(cmd_line_options.plugins)):
                for plugin in exists_poc_with_ext:
                    if openplugin in plugin:
                        logger.info("Load Plugin:{}".format(os.path.join(plugins_dir, plugin)))
                        cmd_line_options.open_lugins.append(os.path.join(plugins_dir, plugin))

    # input_options=cmd_line_parser().__dict__
    # if hasattr(input_options, "items"):
    #     input_options_items = input_options.items()
    # else:
    #     input_options_items = input_options.__dict__.items()
    # for key, value in input_options_items:
    #     if key not in cmd_line_options or value not in (None, False):
    #         cmd_line_options[key] = value


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
    <link href="https://cdn.bootcss.com/prism/9000.0.1/themes/prism.min.css" rel="stylesheet">
    <script src="https://cdn.bootcss.com/prism/9000.0.1/prism.min.js" data-manual></script>
    <script src="https://cdn.bootcss.com/prism/9000.0.1/components/prism-http.min.js"></script>
    <script src="https://cdn.bootcss.com/prism/9000.0.1/components/prism-javascript.min.js"></script>
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
<script src="https://cdn.ravenjs.com/3.19.1/raven.min.js" crossorigin="anonymous"></script>


<div id="vuln-records">'''
