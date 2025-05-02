# -code: utf-8-
# Filename: main.py
# Program_name: Web-Easy-Scanner
# Author: ES
# Last UpDate: 2025/4/31
# Version: 1.1.0

import os
import sys
import random
import socket
import time
import subprocess
import platform
import requests
import threading
import tqdm
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ========================== 配色打印函数 ==========================
def print_red(text):
    print(f"\033[31m{text}\033[0m")

def print_green(text):
    print(f"\033[32m{text}\033[0m")

def print_yellow(text):
    print(f"\033[33m{text}\033[0m")

def print_blue(text):
    print(f"\033[34m{text}\033[0m")

def print_purple(text):
    print(f"\033[35m{text}\033[0m")

# ========================== 漏洞路径列表 ==========================
JBOSS_PATHS = [
    '/jmx-console',
    '/web-console',
    '/invoker/JMXInvokerServlet',
    '/admin-console',
    '/jbossmq-httpil/HTTPServerILServlet',
    '/invoker/readonly'
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
}

DISCLAIMER = """
\033[31m免责声明：本工具仅限合法授权测试，作者不对任何非法用途负责。\033[0m"""

# ========================== 工具函数 ==========================
def resolve_domain(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def get_base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def ping_ip(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    cmd = ['ping', param, '3', ip]
    subprocess.run(cmd)

# ========================== 扫描函数 ==========================
def scan_ports(ip, start=None, end=None):
    lock = threading.Lock()
    open_ports = []

    # 默认常见端口列表
    default_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 1433, 1521, 3306, 3389, 6379, 8080, 8443
    ]

    # 判断使用范围还是默认
    if start is not None and end is not None:
        port_list = list(range(start, end + 1))
        print_green(f"\n开始扫描 {ip} 的端口范围：{start} - {end}\n")
    else:
        port_list = default_ports
        print_green(f"\n未指定范围，使用默认常见端口扫描 {ip}：\n")

    progress = tqdm.tqdm(total=len(port_list), desc="扫描进度", ncols=70)

    def scan_single_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    with lock:
                        open_ports.append((port, service))
                        print_green(f"[端口开放] {port:<5} 服务: {service}")
        except Exception as e:
            with lock:
                print_red(f"[错误] 端口 {port} 扫描失败：{e}")
        finally:
            progress.update(1)

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in port_list:
            executor.submit(scan_single_port, port)

    progress.close()

    if open_ports:
        print_green("\n扫描完成！开放端口如下：")
        for port, service in open_ports:
            print_green(f" - {port:<5} 服务: {service}")
    else:
        print_red("\n未发现开放端口喵～")

# ========================== JBoss 漏洞检查 ==========================
def scan_jboss(base_url):
    print_blue("\n[+] 正在扫描 JBoss 漏洞")
    for path in JBOSS_PATHS:
        url = base_url + path
        try:
            resp = requests.get(url, headers=HEADERS, timeout=3, verify=False)
            if resp.status_code == 401:
                if "jmx" in path:
                    print_purple(f"[警告] jmx-console 可能存在漏洞！地址: {url}")
                elif "web" in path:
                    print_purple(f"[警告] web-console 可能存在漏洞！地址: {url}")
            elif resp.status_code == 200:
                if "admin" in path:
                    print_purple(f"[警告] admin-console 可能存在漏洞！地址: {url}")
                elif "JMXInvokerServlet" in path:
                    print_purple(f"[警告] CVE-2015-7501 JMXInvokerServlet 漏洞！地址: {url}")
                elif "jbossmq" in path:
                    print_purple(f"[警告] CVE-2017-7504 JBOSSMQ 漏洞！地址: {url}")
            elif resp.status_code == 500 and "readonly" in path:
                print_purple(f"[警告] CVE-2017-12149 可能存在漏洞！地址: {url}")
        except:
            continue

# ========================== WebLogic 漏洞检查 ==========================
def scan_weblogic(base_url):
    def check(path, vuln_name):
        url = f"{base_url}{path}" if base_url.endswith('/') else f"{base_url}/{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=3, verify=False)
            if resp.status_code in [200, 403]:
                print_purple(f"[WebLogic] 可能存在 {vuln_name} 漏洞！地址: {url}")
        except:
            pass

    print_blue("\n[+] 正在扫描 WebLogic 漏洞")
    check("uddiexplorer/SearchPublicRegistries.jsp", "SSRF")
    check("ws_utc/config.do", "CVE-2018-2894")
    check("_async/AsyncResponseService", "CVE-2019-1725")

# ========================== SQL I  ============================
def scan_sql(url):
    if "?" in url:
        re_url = url + "'"
    else:
        re_url = url + "?id=1'"

    print_blue("\n[+] 正在扫描 SQL注入 漏洞")
    try:
        r = requests.get(re_url, headers=HEADERS, timeout=3, verify=False)
        if r.status_code == 200:
            if "sql" or "error" in r.text:
                print_purple(f"[SQL]可能存在漏洞: {re_url}")
            else:
                print_blue("[SQL]未发现漏洞")
        else:
            print_purple(f"[SQL]可能存在漏洞: {re_url}")
    except Exception as e:
        print_red(f"[程序错误]在扫描sql中出现错误: {e}")

# ========================= 敏感信息泄露 =========================

def sensitive(base_url):
    print_blue("\n[+] 正在扫描 敏感信息泄露 漏洞")
    se_list = [
        "/.env",
        "/.git",
        "/config",
        "/config.php",
        "/db.sql",
    ]
    norm_list = [
        "/admin",
        "/login",
        "/backup",
        "/.git",
    ]
    for i in se_list:
        try:
            r = requests.get(f"{base_url}{i}", headers=HEADERS, timeout=3, verify=False)
            if r.status_code == 200:
                print_purple(f"[敏感信息]可能存在权限问题：{base_url}{i}")
        except Exception as e:
            pass
        time.sleep(random.randint(0, 2))
    for i in norm_list:
        try:
            r = requests.get(f"{base_url}{i}", headers=HEADERS, timeout=3, verify=False)
            if r.status_code == 200:
                print_purple(f"[敏感信息]可能存在敏感信息：{base_url}{i}")
        except Exception as e:
            pass
        time.sleep(random.randint(0, 2))


# ========================= XSS检测 ============================

def detect_xss(url):
    print_blue("\n[+] 正在扫描 XSS注入 漏洞")

    xss_payloads = [
        "<script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "\" onfocus=alert(1) autofocus x=\""
    ]
    def run(url,param=''):
        for payload in xss_payloads:
            full_url = f"{url}{param}={payload}"
            try:
                res = requests.get(full_url, timeout=5)
                if payload in res.text:
                    print_purple(f"[XSS] 可能存在XSS漏洞：{full_url}")
                    return True
            except Exception as e:
                print_red(f"请求出错：{e}")
    if "?" in url:
        run(url)
    else:
        run(url,param='?id')

# ========================= 命令注入 ===========================
def detect_cmdi(url):
    print_blue("\n[+] 正在扫描 命令注入 漏洞")
    payloads = [
        "test; whoami", "test && whoami", "test | whoami",
        "test`whoami`", "test$(whoami)"
    ]
    indicators = ["root", "uid=", "admin", "bash", "/home", "sh"]

    def run(url,param=''):
        for payload in payloads:
            full_url = f"{url}{param}={payload}"
            try:
                res = requests.get(full_url, timeout=5)
                if any(key in res.text.lower() for key in indicators):
                    print_purple(f"[命令注入] 命令注入疑似成功：{full_url}")
                    return True
            except Exception as e:
                print(f"[命令注入] 请求失败：{e}")
    if "?" in url:
        run(url)
    else:
        run(url,param='?id')


# ========================== 主程序入口 ==========================
def main():
    print(DISCLAIMER)
    requests.packages.urllib3.disable_warnings()

    url = input("\n请输入目标网址（如 http://example.com）: ").strip()
    base_url = get_base_url(url)
    domain = urlparse(url).netloc
    ip = resolve_domain(domain)

    if not ip:
        print_red("[错误] 域名无法解析，请检查输入的网址是否正确。")
        return

    try:
        port_range = input("请输入端口范围（如 1-1000，直接回车则默认常见端口）：").strip()

        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            scan_ports(ip, start, end)
        else:
            scan_ports(ip)  # 默认端口列表
    except:
        print_red("[错误] 端口号应为整数。")
        return
    scan_jboss(base_url)
    sensitive(base_url)
    scan_sql(url)
    detect_xss(url)
    detect_cmdi(url)
    scan_weblogic(base_url)

    try:
        os.system(f'python3 ws.py -t {ip}')
    except Exception as e:
        print_red(f"[weblogic] 调用 ws.py 时出错: {e}")

    input("\n扫描完成，按回车退出...")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print_red(f"总程序运行时发生致命错误: {e}")
        input("按回车退出...")
