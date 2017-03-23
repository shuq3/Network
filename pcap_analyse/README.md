# Pcap文件分析

## 目标
分析pcap文件，提取协议头部信息

## 抓包
* 使用tcpdump工具抓包，[常用的命令行语句](http://www.tecmint.com/12-tcpdump-commands-a-network-sniffer-tool/)
* 使用curl发送数据请求，[常用的命令行语句](https://curl.haxx.se/docs/httpscripting.html)

## 分析
* 使用[dkpt](http://www.commercialventvac.com/dpkt.html)的python依赖，读取pcap文件，提取文件中的数据包信息

## 运行
* 安装python2x版本
* 安装pip
1. 下载[get-pip.py](https://bootstrap.pypa.io/get-pip.py)
2. 运行get-pip.py `python get-pip.py`
* 安装dkpt `pip install dpkt`
* 修改parse.py中的文件名称并运行 `python parse.py`
