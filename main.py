# -code: utf-8-
# Filename: main.py
# Program_name: ES_scanner
# Author: ES
# Last UpDate: 2025/1/16
# Version: 1.0.2

import socket
import sys
from urllib.parse import urlparse
import requests
import time
import subprocess
import platform
import os


def red_print(text):
	print(f"\033[31m{text}\033[0m")

def green_print(text):
	print(f"\033[32m{text}\033[0m")

def yellow_print(text):
	print(f"\033[33m{text}\033[0m")

def blue_print(text):
	print(f"\033[34m{text}\033[0m")

def purple_print(text):
	print(f"\033[35m{text}\033[0m")
try:
	mian_ze = """免责声明：
本漏洞扫描脚本仅供合法授权的安全测试和研究使用。
使用者应确保在合法的范围内使用本脚本，不得用于任何非法或未经授权的入侵、攻击等行为。
对于因使用本脚本而产生的任何法律后果，本脚本的作者和提供者不承担任何责任。
使用者应充分理解并遵守相关法律法规，合理合法地使用本脚本。"""
	requests.packages.urllib3.disable_warnings()

	headers = {
		"User-Agent":"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
	}

	vuls=['/jmx-console','/web-console','/invoker/JMXInvokerServlet','/admin-console','/jbossmq-httpil/HTTPServerILServlet','/invoker/readonly']


	def ping_ip(ip_address, count=3):
		param = '-n' if platform.system().lower() == 'windows' else '-c'
		command = ['ping', param, str(count), ip_address]

		try:
			# 使用subprocess.run()执行命令，并捕获输出
			result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

			# 判断是否能ping通
			if result.returncode == 0:
				pass
			else:
				print(f"{ip_address} ip异常可能是某个错误导致{result.stdout}")
		except Exception as e:
			print(f"执行ping命令时出错：{e}")

	def jboss(target_url):
		target = target_url
		target=target.strip()
		print("\033[94m[jboss]扫描地址为：" + target + "\033[0m")
		for listt in vuls:
			listt = listt.strip()
			url = target + listt
			try:
				r = requests.get(url, headers=headers, timeout=3, verify=False)

				#jmx-console
				#web-console
				if r.status_code == 401:
					if "jmx" in url:
						print("\033[95m[警告]jmx-console可能存在漏洞！\033[0m")
					elif "web" in url:
						print("\033[95m[警告]web-console可能存在漏洞！\033[0m")
					else:
						pass
				else:
					pass

				#admin-console
				#JBoss JMXInvokerServlet(CVE-2015-7501)
				#JBOSSMQ JMS(CVE-2017-7504)
				if r.status_code == 200:
					if "admin" in url:
						print("\033[95m[警告]admin-console可能存在漏洞！\033[0m")
					elif "JMXInvokerServlet" in url:
						print("\033[95m[警告]JBoss JMXInvokerServlet(CVE-2015-7501) 可能存在漏洞！\033[0m")
					elif "jbossmq" in url:
						print("\033[95m[警告]JBOSSMQ JMS(CVE-2017-7504) 可能存在漏洞！\033[0m")
					else:
						pass
				else:
					pass

				#(CVE-2017-12149)
				if r.status_code == 500:
					if "readonly" in url:
						print("\033[95m[警告]漏洞版本号：CVE-2017-12149，可能存在漏洞！\033[0m")
					else:
						pass
				else:
					pass

			except Exception as e:
				pass

	def scan_ports(target, start_port, end_port):
		global port
		try:
			# 尝试解析域名
			ip = socket.gethostbyname(target)
			print(f"\033[92m扫描目标: {target} ({ip})\033[0m")
		except socket.gaierror:
			print("\033[91m[主程序]无法解析域名或IP地址\033[0m")
			print('[主程序]是否直接使用url进行扫描:(y/n)')
			choss = input('>>>')
			if choss == 'n':
				sys.exit()
			else:
				return
		tie = 0
		print('=================')
		while tie != 3:
			try:
				for port in range(start_port, end_port + 1):
					# print(f"正在扫描端口 {port}...")  # 在扫描每个端口之前打印
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.settimeout(0.12)  # 设置超时时间为0.12秒

					result = sock.connect_ex((ip, port))
					if result == 0:
						service = socket.getservbyport(port)
						if service:
							print(f"\033[92m[主程序]端口 {port} 是开放的，服务: {service}\033[0m")
						else:
							print(f"\033[95m[主程序]端口 {port} 是开放的，服务: unknown\033[0m")
					else:
						pass #如果未开放则不打印

					sock.close()
				break
			except KeyboardInterrupt:
				print("\033[91m[主程序]扫描被用户中断\033[0m")
			except socket.error:
				tie += 1
				print(f"\033[91m[发生错误]位置：端口{port}\033[0m")
				start_port = port + 1
		return ip
	def weblogic_ssrf(target_url):
		headers = {
			"User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
		}
		if target_url[-1] == '/':
			response = requests.get(f"{target_url}uddiexplorer/SearchPublicRegistries.jsp",headers=headers)
			lo = f"{target_url}uddiexplorer/SearchPublicRegistries.jsp"
		else:
			response = requests.get(f"{target_url}/uddiexplorer/SearchPublicRegistries.jsp", headers=headers)
			lo = f"{target_url}/uddiexplorer/SearchPublicRegistries.jsp"
		if response.status_code == 200:
			purple_print(f'[weblogic]可能存在SSRF漏洞，漏洞地址：{lo}')
		else:
			pass
	def weblogic_CVE_2019_1725(base_url):
		headers = {
			"User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
		}
		if base_url[-1] == '/':
			response = requests.get(f"{base_url}_async/AsyncResponseService",headers=headers)
			lo = f"{base_url}_async/AsyncResponseService"
		else:
			response = requests.get(f"{base_url}/_async/AsyncResponseService", headers=headers)
			lo = f"{base_url}/_async/AsyncResponseService"
		if response.status_code == 200:
			purple_print(f"[weblogic]存在CVE—2019—1725漏洞位置为：{lo}")
		elif response.status_code == 403:
			purple_print(f"[weblogic]可能存在CVE—2019—1725漏洞位置为：{lo}")
		else:
			pass


	def get_base_url(url):
		# 解析网址
		parsed_url = urlparse(url)
		# 重新组合协议和域名部分
		base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
		return base_url
	def weblogic_CVE_2018_2894(url):
		headers = {
			"User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
		}
		if url[-1] == '/':
			response = requests.get(f"{url}ws_utc/config.do",headers=headers)
			lo = f"{url}ws_utc/config.do"
		else:
			response = requests.get(f"{url}/ws_utc/config.do", headers=headers)
			lo = f"{url}/ws_utc/config.do"
		if response.status_code == 200:
			purple_print(f'[weblogic]可能存在漏洞：CVE-2018-2894;漏洞地址：{lo}')
		else:
			pass

	if __name__ == "__main__":
		try:
			# 获取当前Python文件的绝对路径
			current_file_path = os.path.abspath(__file__)
			# 获取当前Python文件所在的目录
			current_directory = os.path.dirname(current_file_path)

			# 更改工作目录到当前Python文件所在的目录
			os.chdir(current_directory)
			red_print(mian_ze)
			target_url = input("[主程序]请输入要扫描的网址: ")

			parsed_url = urlparse(target_url)
			target = parsed_url.netloc  # 提取域名部分
			base_url = get_base_url(target_url)
			print(f"[主程序]基础网址：{base_url}")

			start_port = int(input("[主程序]请输入起始端口: "))
			end_port = int(input("[主程序]请输入结束端口: "))

			target_ip = scan_ports(target, start_port, end_port)

			green_print('==中间件漏洞扫描==')
			blue_print('=====Jboss=====')
			jboss(base_url)
			blue_print('===Jboss扫描结束===')
			blue_print('=====weblogic=====')
			weblogic_ssrf(base_url)
			weblogic_CVE_2018_2894(base_url)
			weblogic_CVE_2019_1725(base_url)
			try:
				os.system('python3 ws.py -t' + target_ip)
			except Exception as e:
				red_print(f'==weblogic扫描器出错{e}==')
				red_print('[主程序]程序已跳过错误继续执行')

			print('\033[92m[weblogic]结束扫描\033[0m')

			blue_print('=====扫描结束，按回车以退出=====')
			input(">>>")
		except Exception as e:
			red_print('报错:')
			red_print(e)
			input('[主程序]按下回车退出>>>')


except Exception as e:
	red_print('报错:')
	red_print(e)
	input('[主程序]按下回车退出>>>')
