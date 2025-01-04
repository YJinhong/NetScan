# -*- coding: UTF-8 -*-
"""
Author: YJinhong
Repositories: https://github.com/YJinhong/NetScan.git
Version: 1.0.0
"""
import scapy.all as scapy
import nmap
import concurrent.futures
import socket
import os
import logging
import tkinter as tk
from tkinter import ttk
import threading
import tkinter.filedialog as filedialog
import csv
import json

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

LANGUAGES = {
    "English": {
        "select_scan_range": "Select Scan Range:",
        "start_scan": "Start Scan",
        "pause": "Pause",
        "continue": "Continue",
        "program_status": "Program status:",
        "waiting_for_scan": "Waiting for scan",
        "scanned_ip": "Scanned IP:",
        "export_results": "Export Results",  
        "scan_completed": "Scan completed",
        "select_language": "Select Language:",
    },
    "简体中文": {
        "select_scan_range": "选择扫描范围：",
        "start_scan": "开始扫描",
        "pause": "暂停",
        "continue": "继续",
        "program_status": "程序状态：",
        "waiting_for_scan": "等待扫描",
        "scanned_ip": "已扫描 IP：",
        "export_results": "导出结果",  
        "scan_completed": "扫描完成",
        "select_language": "选择语言：",
    },
    '繁體中文': {
        'select_scan_range': '選擇掃描範圍:',
        'start_scan': '開始掃描',
        'pause': '暫停',
        "continue": "繼續",
        "program_status": "程序狀態：",
        "waiting_for_scan": "等待掃描",
        "scanned_ip": "已掃描 IP：",
        "export_results": "導出結果",  
        "scan_completed": "掃描完成",
        "select_language": "選擇語言：",    
    },
    "Español": {
        "select_scan_range": "Seleccionar rango de escaneo:",
        "start_scan": "Iniciar escaneo",
        "pause": "Pausa",
        "continue": "Continuar",
        "program_status": "Estado del programa:",
        "waiting_for_scan": "Esperando escaneo",
        "scanned_ip": "IP escaneada:",
        "export_results": "Exportar resultados",  
        "scan_completed": "Escaneo completado",
        "select_language": "Seleccionar idioma:",
    },
    "Français": {
        "select_scan_range": "Sélectionnez la plage de balayage :",
        "start_scan": "Démarrer le scan",
        "pause": "Pause",
        "continue": "Continuer",
        "program_status": "État du programme :",
        "waiting_for_scan": "En attente du scan",
        "scanned_ip": "IP scannée :",
        "export_results": "Exporter les résultats",  
        "scan_completed": "Scan terminé",
        "select_language": "Sélectionner la langue :",
    },
    "한국어": {
        "select_scan_range": "스캔 범위 선택:",
        "start_scan": "스캔 시작",
        "pause": "일시 중지",
        "continue": "계속",
        "program_status": "프로그램 상태:",
        "waiting_for_scan": "스캔 대기 중",
        "scanned_ip": "스캔된 IP:",
        "export_results": "결과 내보내기",  
        "scan_completed": "스캔 완료",
        "select_language": "언어 선택:",
    },
}

current_language = "English"

def translate(key):
    """根据当前语言翻译文本"""
    return LANGUAGES[current_language].get(key, key)


# 解析 Nmap 输出
def get_device_info_nmap(ip):
    try:
        logging.info(f"Scanning IP {ip} using nmap...")
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-p 80,443,21,22,23,8080,445,3306,3389,161 -O -sV")

        if ip in nm.all_hosts():
            open_ports = nm[ip].get("tcp", {})
            os_info = nm[ip].get("osmatch", [])
            service_info = nm[ip].get("hostnames", [])

            device_name = ', '.join([hostname['name'] for hostname in service_info]) if service_info else "Unknown"
            device_type = get_device_type(open_ports)  # 获取设备类型
            os_info = os_info[0]['name'] if os_info else "Unknown"

            # 判断是否有防火墙
            is_firewall = "No"
            if len(nm[ip].all_tcp()) == 0:  # 如果没有开放任何端口，可能存在防火墙
                is_firewall = "Yes"

            online_status = "Online" if ip in nm.all_hosts() else "Offline"
        else:
            logging.warning(f"IP {ip} is unreachable or no information found.")
            device_type = "Device Unreachable or Unknown"
            os_info = "Unknown"
            device_name = "Unknown"
            online_status = "Offline"
            is_firewall = "Unknown"
    except Exception as e:
        logging.error(f"Error scanning {ip}: {str(e)}")
        device_type = "Error: " + str(e)
        os_info = "Unknown"
        device_name = "Unknown"
        online_status = "Offline"
        is_firewall = "Unknown"

    return device_type, device_name, os_info, online_status, is_firewall

# 获取设备类型
def get_device_type(open_ports):
    device_type = "Unknown"
    if 80 in open_ports or 443 in open_ports:
        device_type = "Web Server or Router"
    elif 21 in open_ports or 22 in open_ports:
        device_type = "FTP or SSH Server"
    elif 23 in open_ports:
        device_type = "Telnet Server"
    elif 8080 in open_ports:
        device_type = "Proxy Server or Camera"
    elif 445 in open_ports:
        device_type = "SMB (File Sharing) Server"
    elif 3306 in open_ports:
        device_type = "MySQL Database Server"
    elif 3389 in open_ports:
        device_type = "Remote Desktop (RDP) Server"
    else:
        device_type = "Other Device"
    
    return device_type

# 获取设备的 DNS 主机名（反向 DNS 解析）
def get_device_dns_name(ip):
    try:
        logging.info(f"Resolving DNS for {ip}...")
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]  # 返回设备主机名
    except socket.herror:
        logging.warning(f"DNS resolution failed for {ip}")
        return "Unknown"

# 多进程扫描网络中的设备
def scan_network(network, update_ui_callback, timeout, pause_event):
    logging.info(f"Starting ARP scan on network {network} with timeout {timeout}s...")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    devices = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
    
    device_list = []
    num_threads = min(50, os.cpu_count() * 2)  # 动态调整线程池大小

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        
        for element in devices:
            ip = element[1].psrc
            mac = element[1].hwsrc
            futures.append(executor.submit(process_device, ip, mac, pause_event))
        
        for future in concurrent.futures.as_completed(futures):
            device_info = future.result()
            device_list.append(device_info)
            update_ui_callback(device_info['ip'])  # 更新 UI 显示
    
    logging.info("Network scan completed.")
    return device_list

def process_device(ip, mac, pause_event):
    logging.info(f"Processing device {ip}...")
    
    # 等待暂停事件
    pause_event.wait()

    device_type_nmap, device_name_nmap, os_info_nmap, online_status, is_firewall = get_device_info_nmap(ip)
    dns_name = get_device_dns_name(ip)
    
    return {
        "ip": ip,
        "mac": mac,
        "type_nmap": device_type_nmap,
        "name_nmap": device_name_nmap,
        "os_nmap": os_info_nmap,
        "dns_name": dns_name,
        "online_status": online_status,
        "firewall_status": is_firewall
    }

def switch_language(language_name):
    global current_language
    if language_name == "Simplified Chinese":
        current_language = "简体中文"
    elif language_name == "Traditional Chinese":
        current_language = "繁體中文"
    else:
        current_language = language_name

    update_ui_language()

def update_ui_language():
    scan_range_label.config(text=LANGUAGES[current_language]['select_scan_range'])
    scan_button.config(text=LANGUAGES[current_language]['start_scan'])
    pause_button.config(text=LANGUAGES[current_language]['pause'])
    language_label.config(text=LANGUAGES[current_language]['select_language'])
    status_label.config(text=LANGUAGES[current_language]['waiting_for_scan'])
    export_button.config(text=LANGUAGES[current_language]['export_results'])

# 在UI中更新IP的显示
def update_ip_display(ip):
    ip_display.config(state=tk.NORMAL)  # 临时启用编辑模式来插入内容
    ip_display.insert(tk.END, f"Scanned IP: {ip}\n")
    ip_display.yview(tk.END)
    ip_display.config(state=tk.DISABLED)  # 恢复为只读模式

# 使用Treeview表格显示设备信息
def display_devices(devices):
    for item in device_table.get_children():
        device_table.delete(item)  # 清除旧的设备信息

    for device in devices:
        device_table.insert("", tk.END, values=(device['ip'], device['mac'], device['type_nmap'], device['name_nmap'], device['os_nmap'], device['dns_name']))

# 使用Treeview表格显示目标主机的在线状态、是否存在防火墙等信息
def display_target_status(devices):
    for item in target_status_table.get_children():
        target_status_table.delete(item)  # 清除旧的设备信息

    for device in devices:
        target_status_table.insert("", tk.END, values=(device['ip'], device['online_status'], device['firewall_status']))

# 执行扫描的线程函数
def start_scan_thread(network_range, timeout, pause_event):
    global is_paused  # 检查是否暂停
    try:
        update_status("Scanning...")  # 在扫描开始时更新状态
        devices = scan_network(network_range, update_ip_display, timeout, pause_event)
        display_devices(devices)
        display_target_status(devices)
        update_status("Scan completed")  # 扫描完成后更新状态
    except KeyboardInterrupt:
        update_status("Scan interrupted by user")  # 如果用户中断了扫描
        logging.info("\nScan interrupted by user.")
    except Exception as e:
        update_status(f"Scan failed: {str(e)}")  # 如果发生异常，更新为失败状态
        logging.error(f"Error: {str(e)}")

# 更新状态栏的内容
def update_status(message):
    status_label.config(text=f"Program status: {message}")

# 根据选择的扫描范围来确定网络段和超时时间
def start_scan(scan_range):
    global is_paused  # 检查是否暂停
    
    # 如果当前处于暂停状态，点击“开始扫描”按钮后，先将“继续”按钮改回“暂停”
    if is_paused:
        pause_button.config(text="Pause")
        update_status("Scanning...")  # 在扫描开始时更新状态
    
    if scan_range == "Home/Small Office":
        network_range = "192.168.1.0/24"
        timeout = 5
    elif scan_range == "Private IP Range":
        network_range = "10.0.0.0/8"
        timeout = 10
    elif scan_range == "Public IP Range":
        network_range = "203.0.113.0/24"
        timeout = 10
    
    # 创建并启动暂停事件
    global pause_event
    pause_event = threading.Event()
    pause_event.set()  # 初始化为“继续”状态

    start_scan_thread(network_range, timeout, pause_event)

# 控制扫描暂停/继续的函数
def toggle_pause():
    global is_paused, pause_event, pause_button
    if is_paused:
        # 继续扫描
        pause_event.set()
        pause_button.config(text="Pause")
        update_status("Scanning...")
    else:
        # 暂停扫描
        pause_event.clear()
        pause_button.config(text="Continue")
        update_status("Scan paused")
    
    is_paused = not is_paused  # 切换暂停/继续状态

is_paused = False  # 默认未暂停
pause_event = threading.Event()  # 暂停事件

# 创建主界面
def create_ui():
    global root, ip_display, device_table, target_status_table, network_combobox, scan_button, status_label, pause_button
    global scan_range_label, language_label, language_combobox, export_button  # 将需要的变量设置为全局

    root = tk.Tk()  # 在函数中定义root
    root.title("NetScan")
    
    # 上半部分：扫描进度展示区域，左对齐
    ip_display_frame = tk.Frame(root)
    ip_display_frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    ip_display = tk.Text(ip_display_frame, height=10, width=50, wrap=tk.WORD)
    ip_display.pack()
    ip_display.config(state=tk.DISABLED)

    # 第二部分：选择扫描范围和开始扫描按钮
    scan_range_frame = tk.Frame(root)
    scan_range_frame.grid(row=1, column=0, padx=10, pady=10, sticky="w")

    scan_range_label = tk.Label(scan_range_frame, text=LANGUAGES[current_language]['select_scan_range'])
    scan_range_label.pack(side=tk.LEFT, padx=5)

    network_combobox = ttk.Combobox(scan_range_frame, values=["Home/Small Office", "Private IP Range", "Public IP Range"], state="readonly")
    network_combobox.set("Home/Small Office")  # 默认值
    network_combobox.pack(side=tk.LEFT, padx=5)

    scan_button = tk.Button(scan_range_frame, text=LANGUAGES[current_language]['start_scan'], command=lambda: threading.Thread(target=start_scan, args=(network_combobox.get(),)).start())
    scan_button.pack(side=tk.LEFT, padx=5)

    # 添加暂停/继续按钮
    pause_button = tk.Button(scan_range_frame, text=LANGUAGES[current_language]['pause'], command=toggle_pause)
    pause_button.pack(side=tk.LEFT, padx=5)

    # 创建语言选择区域并放置在暂停按钮右边
    language_frame = tk.Frame(scan_range_frame)  
    language_frame.pack(side=tk.LEFT, padx=5)

    # 添加语言选择标签
    language_label = tk.Label(language_frame, text=LANGUAGES[current_language]['select_language'])
    language_label.pack(side=tk.LEFT, padx=5)

    # 创建语言选择下拉菜单
    language_combobox = ttk.Combobox(language_frame, values=["English", "简体中文", "繁體中文", "Español", "Français", "한국어"], state="readonly")
    language_combobox.set("English")  # 默认选择英语
    language_combobox.pack(side=tk.LEFT, padx=5) 
    language_combobox.bind("<<ComboboxSelected>>", lambda event: switch_language(language_combobox.get()))  # 绑定语言切换事件

    # 添加“导出扫描结果”按钮，放置在语言选择旁边
    export_button = tk.Button(language_frame, text=LANGUAGES[current_language]['export_results'], command=export_scan_results)
    export_button.pack(side=tk.LEFT, padx=5)

    # 第三部分：设备信息展示区域
    device_table_frame = tk.Frame(root)
    device_table_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
    
    device_table = ttk.Treeview(device_table_frame, columns=("IP Address", "MAC Address", "Type", "Device Name", "OS", "DNS Name"), show="headings")
    device_table.pack(fill=tk.BOTH, expand=True)

    # 更新语言选择部分
    device_table.heading("IP Address", text=LANGUAGES[current_language]['scanned_ip'])
    device_table.heading("MAC Address", text="MAC Address")
    device_table.heading("Type", text="Type")
    device_table.heading("Device Name", text="Device Name")
    device_table.heading("OS", text="OS")
    device_table.heading("DNS Name", text="DNS Name")
    
    # 设置列宽
    device_table.column("IP Address", width=120)
    device_table.column("MAC Address", width=150)
    device_table.column("Type", width=300)
    device_table.column("Device Name", width=250)
    device_table.column("OS", width=150)
    device_table.column("DNS Name", width=150)

    # 第四部分：目标主机状态展示区域
    target_status_frame = tk.Frame(root)
    target_status_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
    
    target_status_table = ttk.Treeview(target_status_frame, columns=("IP Address", "Online Status", "Firewall Status"), show="headings")
    target_status_table.pack(fill=tk.BOTH, expand=True)

    # 设置列标题
    target_status_table.heading("IP Address", text="IP Address")
    target_status_table.heading("Online Status", text="Online Status")
    target_status_table.heading("Firewall Status", text="Firewall Status")
    
    # 设置列宽
    target_status_table.column("IP Address", width=120)
    target_status_table.column("Online Status", width=150)
    target_status_table.column("Firewall Status", width=150)

    # 状态栏
    status_frame = tk.Frame(root)
    status_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
    
    status_label = tk.Label(status_frame, text=LANGUAGES[current_language]['waiting_for_scan'], anchor="w")
    status_label.pack(fill=tk.X)

    root.mainloop()

# 导出扫描结果的函数
def export_scan_results():
    # 选择文件保存路径和文件名
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")])
    
    if file_path:
        # 获取扫描结果
        devices = [{'ip': '192.168.1.1', 'mac': '00:14:22:01:23:45', 'type_nmap': 'Router', 'name_nmap': 'Device 1', 'os_nmap': 'Linux', 'dns_name': 'router.local'}]  # 示例数据
        
        if file_path.endswith(".csv"):
            save_as_csv(devices, file_path)
        elif file_path.endswith(".json"):
            save_as_json(devices, file_path)

# 保存为CSV文件
def save_as_csv(devices, file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["ip", "mac", "type_nmap", "name_nmap", "os_nmap", "dns_name"])
        writer.writeheader()
        for device in devices:
            writer.writerow(device)
    logging.info(f"Scan results saved as CSV to {file_path}")

# 保存为JSON文件
def save_as_json(devices, file_path):
    with open(file_path, mode='w') as file:
        json.dump(devices, file, indent=4)
    logging.info(f"Scan results saved as JSON to {file_path}")

   
if __name__ == "__main__":
    create_ui()
