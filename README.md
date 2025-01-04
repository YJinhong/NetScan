# WiFi连接用户扫描工具

## 免责声明

**本项目所涉及的技术、思路和工具仅供学习交流，任何人不得将其用于非法用途和盈利，不得将其用于非授权渗透测试，否则后果自行承担，与本项目无关。**

## 项目介绍

NetScan是一款轻量级的网络扫描工具，支持多语言。它结合了 ICMP 回显请求（Ping）与端口扫描功能，能够快速识别网络中的活动设备和开放端口，同时支持动态调整线程池大小，以优化扫描效率。

## 如何使用

#### 简单使用

##### 使用

git clone https://github.com/YJinhong/NetScan.git
cd NetScan

安装依赖：
pip install -r requirements.txt

运行程序：
python main.py

安装Nmap：
https://nmap.org/

##### 结果

扫描结果会显示在日志中，同时以清晰的列表形式呈现在GUI中。

#### 自动运行

##### 使用

1. 选择扫描区域。
2. 点击“开始扫描”。
3. 查看扫描结果。

##### 结果

扫描完成后，结果会自动显示，包含设备IP地址、MAC地址及开放端口信息。

#### 日志

## 开发环境

Python ≥ 3.8

## 核心模块

scapy
pyside6

## 系统要求

- Windows 10 及以上
- Ubuntu 22.04 及以上版本（实验性）
- 其它支持 Python 3.8.x 的Linux系统（实验性）
- 提示：支持Windows和Linux，暂不支持MacOS。

## 如何修改GUI

1. 安装Python和所需模块：
   ip install -r requirements.txt

2. 启动QT Designer：

   pyside6-designer

3. 在QT Designer中打开 netscan_gui.ui 文件，调整UI后保存。

## 更新日志

### v1.0.0

- 初始版本发布。
- 支持ICMP回显请求扫描功能。
- 支持动态调整线程池大小。
- 支持多频段扫描功能。
- 支持语言：
  - 简体中文
  - 繁體中文
  - English
  - Español
  - Français
  - 한국어
