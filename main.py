#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports
import os, shodan, time, math, argparse
from rainbow import *
from colorama import Fore
from datetime import datetime

def clear() -> None:
	"""Funcion para realizar un clear en la terminal segun el sistema operativo"""
	os.system('cls' if os.name == 'nt' else 'clear')

def check_key(api_key: str) -> bool:
	"""Verifica si una clave de API de Shodan es válida y funcional.

    Intenta conectar con la API de Shodan y recuperar la información de la cuenta
    para confirmar que la clave tiene permisos correctos.

    Args:
        api_key (str): La API Key de Shodan.

    Returns:
        bool: True si la clave es válida y la conexión es exitosa, 
              False si la clave es rechazada o hay un error de API.
    """
	try:
		api = shodan.Shodan(api_key)
		api.info()
		return True
	except shodan.APIError:
		return False

def read_env() -> str:
	"""Intenta leer la clave del archivo .env de forma segura."""

	if not os.path.exists(".env"):
		return ""

	try:
		with open(".env","r") as f:
			for l in f:
				if l.strip().startswith("SHODAN_KEY="):
					return l.split("=", 1)[1].strip()
	except (IOError, IndexError):
		return ""
	
	return ""

def banner() -> None:
	print(rainbow("""▄█████ ▄▄ ▄▄  ▄▄▄  ▄▄▄▄   ▄▄▄  ▄▄  ▄▄ 
▀▀▀▄▄▄ ██▄██ ██▀██ ██▀██ ██▀██ ███▄██ 
█████▀ ██ ██ ▀███▀ ████▀ ██▀██ ██ ▀██ 
						By CrIsTiiAnPvP
██      ▄▄▄   ▄▄▄  ▄▄ ▄▄ ██  ██ ▄▄▄▄  
██     ██▀██ ██▀██ ██▄█▀ ██  ██ ██▄█▀ 
██████ ▀███▀ ▀███▀ ██ ██ ▀████▀ ██                           
"""))

def format_output(mode: str, data: dict, comes_from: str = "interactive") -> list:
	if mode == "ip":
		output = []
		vulns = {}
		techs = {}
		width_title = 50
		ORANGE = "\033[38;2;255;153;0m"

		# Tags
		if data.get('tags', []):
			output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Tags: {Fore.YELLOW}{f' {Fore.LIGHTMAGENTA_EX}|{Fore.YELLOW} '.join(data.get('tags', []))}{Fore.RESET}")
		
		# Basic Info
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}IP Address: {Fore.YELLOW}{data.get('ip_str', 'N/A')} {Fore.LIGHTMAGENTA_EX}| {Fore.YELLOW}{data.get('city', 'N/A')} ({data.get('country_name', 'N/A')}/{data.get('region_code', 'N/A')}){Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Latitude: {Fore.YELLOW}{data.get('latitude', 'N/A')} {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Longitude: {Fore.YELLOW}{data.get('longitude', 'N/A')}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Organization: {Fore.YELLOW}{data.get('org', 'N/A')}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}ISP: {Fore.YELLOW}{data.get('isp', 'N/A')}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Hostnames: {Fore.YELLOW}{', '.join(data.get('hostnames', [])) if data.get('hostnames') else 'N/A'} {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Domains: {Fore.YELLOW}{', '.join(data.get('domains', [])) if data.get('domains') else 'N/A'}{Fore.RESET}")
		
		# Cloud Computing
		for service in data.get('data', []):
			cloud = service.get('cloud', {})
			if cloud:
				provider, region, service = cloud.get('provider', 'N/A'), cloud.get('region'), cloud.get('service')
				cloud_str = f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Cloud Info: {Fore.YELLOW}{provider}"
				if region:
					cloud_str += f" {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Region: {Fore.YELLOW}{region}"
				if service:
					cloud_str += f" {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Service: {Fore.YELLOW}{service}"
				output.append(cloud_str + Fore.RESET)
				break

		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Operating System: {Fore.YELLOW}{data.get('os', 'N/A')}{Fore.RESET}")
		
		# Last Update Formatting
		try:
			dt_object = datetime.strptime(data.get('last_update', '').split('.')[0], "%Y-%m-%dT%H:%M:%S")
			final_date = dt_object.strftime('%d-%m-%Y %H:%M:%S')
		except (ValueError, AttributeError):
			final_date = "Unknown"
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Last Update: {Fore.YELLOW}{final_date}{Fore.RESET}")

		# Technologies
		for p in data.get('data', []):
			components = p.get('http', {}).get('components', {})
			if components:
				for name, details in components.items():
					v = details.get('versions', [])
					v_str = f" v{v[0]}" if v else ""
					full_name = f"{name}{v_str}"
					for cat in details.get('categories', ['Other']):
						if cat not in techs:
							techs[cat] = set()
						techs[cat].add(full_name)
		if techs:
			title = "Technologies"
			fill = int((width_title - len(title) - 2) / 2)
			bar = '=' * fill
			output.append(f"\n{Fore.WHITE}[{rainbow(bar)} {Fore.WHITE}{title} {rainbow(bar)}{Fore.WHITE}]")
			output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.LIGHTMAGENTA_EX}Detected Technologies (Global Summary):{Fore.RESET}")
			tech_items = list(techs.items())
			total_items = len(tech_items)
			for i, (cat, tech_set) in enumerate(techs.items()):
				symbol = "└─" if i == total_items - 1 else "├─"
				formatted_list = [f"{Fore.YELLOW}{t}{Fore.RESET}" for t in sorted(tech_set)]
				tech_string = f"{Fore.LIGHTBLACK_EX}, ".join(formatted_list)
				output.append(f"    {Fore.LIGHTMAGENTA_EX}│  {Fore.CYAN}{symbol} {cat}: {tech_string}")
			output.append(f"{Fore.WHITE}[{rainbow('='*width_title)}{Fore.WHITE}]")

		# Services & Ports
		title = "Services & Ports"
		fill = int((width_title - len(title) - 2) / 2)
		bar = '=' * fill
		output.append(f"\n{Fore.WHITE}[{Fore.BLUE}{bar} {Fore.WHITE}{title} {Fore.BLUE}{bar}{Fore.WHITE}]")
		for p in data.get('data', []):
			output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Port: {Fore.YELLOW}{p.get('port', 'N/A')}/{p.get('transport', 'tcp')} {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Product: {Fore.YELLOW}{p.get('product', 'N/A')}{Fore.RESET}")
			if p.get('vulns'):
				output[-1] += f" {Fore.LIGHTMAGENTA_EX}| {Fore.RED}Vulnerabilities: {Fore.YELLOW}{', '.join(p.get('vulns').keys())}{Fore.RESET}"	
			for cve, details in p.get('vulns', {}).items():
				try:
					cvss = float(details.get('cvss', 0.0))
				except (ValueError, TypeError):
					cvss = 0.0
				vulns[cve] = {
                    "cvss": cvss, 
                    "summary": details.get('summary', 'N/A')
                }
				
		output.append(f"{Fore.WHITE}[{Fore.BLUE}{'='*width_title}{Fore.WHITE}]")

		# Vulnerabilities
		if vulns:
			sorted_vulns = sorted(vulns.items(), key=lambda x: x[1]['cvss'], reverse=True)
			show_details = True
			if len(vulns) >5:
				for line in output:
					print(line)
				output = []
				if comes_from == "interactive":
					print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Found {Fore.YELLOW}{len(vulns)}{Fore.RED} vulnerabilities.\n")
					choice = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Show descriptions for each vulnerability? (y/N):')} {Fore.RESET}").lower().strip()
					if choice != 'y':
						show_details = False

			title = "Vulnerabilities"
			fill = int((width_title - len(title) - 2) / 2)
			bar = '=' * fill
			output.append(f"\n{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{bar} {Fore.WHITE}{title} {Fore.LIGHTMAGENTA_EX}{bar}{Fore.WHITE}]")
			
			if not show_details:
				categories = {
					"Critical": [], "High": [], "Medium": [], "Low": [], "None": []
				}
				for cve, data in sorted_vulns:
					cvss = data['cvss']
					if cvss >= 9.0:
						cat = "Critical"; color = Fore.RED 
					elif cvss >= 7.0:
						cat = "High"; color = ORANGE
					elif cvss >= 4.0:
						cat = "Medium"; color = Fore.YELLOW
					elif cvss > 0.0:
						cat = "Low"; color = Fore.GREEN
					else:
						cat = "None"; color = Fore.WHITE
					categories[cat].append(f"{color}{cve} {Fore.LIGHTBLACK_EX}(CVSS: {cvss}){Fore.RESET}")
				
				for cat, items in categories.items():
					if items:
						count = len(items)
						if cat == "Critical": cat_color = Fore.RED
						elif cat == "High": cat_color = ORANGE
						elif cat == "Medium": cat_color = Fore.YELLOW
						elif cat == "Low": cat_color = Fore.GREEN
						else: cat_color = Fore.WHITE
						output.append(f"{Fore.WHITE}({Fore.CYAN}{count}{Fore.WHITE}) {cat_color}{cat}:{Fore.RESET}")

						for i, item_str in enumerate(items):
							symbol = "└─" if i == len(items) - 1 else "├─"
							output.append(f"    {Fore.LIGHTMAGENTA_EX}{symbol} {item_str}")
			else:
				for cve, data in sorted_vulns:
					score = data['cvss']
					if score >= 9.0: cvss_color = Fore.RED
					elif score >= 7.0: cvss_color = ORANGE
					elif score >= 4.0: cvss_color = Fore.YELLOW
					elif score > 0.0: cvss_color = Fore.GREEN
					else: cvss_color = Fore.WHITE
					output.append(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] ({cvss_color}{score}{Fore.WHITE}) {Fore.RED}Vulnerability: {Fore.YELLOW}{cve}{Fore.RESET} {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Details: {Fore.WHITE}{data['summary']}{Fore.RESET}")
					if len(vulns) > 1: output.append("")

			output.append(f"{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{'='*width_title}{Fore.WHITE}]")

		return output

	elif mode == "query":
		output = []
		try:
			dt_object = datetime.strptime(data.get('timestamp', '').split('.')[0], "%Y-%m-%dT%H:%M:%S")
			final_date = dt_object.strftime('%d-%m-%Y %H:%M:%S')
		except (ValueError, AttributeError):
			final_date = "Unknown"
		
		product = data.get('product') or data.get('os') or 'N/A'

		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}IP Address: {Fore.YELLOW}{data.get('ip_str', 'N/A')} {Fore.LIGHTMAGENTA_EX}| {Fore.YELLOW}{data.get('location', {}).get('city', 'N/A')} ({data.get('location', {}).get('country_name', 'N/A')}/{data.get('location', {}).get('region_code', 'N/A')}){Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Organization: {Fore.YELLOW}{data.get('org', 'N/A')}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}ISP: {Fore.YELLOW}{data.get('isp', 'N/A')}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}Port: {Fore.YELLOW}{data.get('port', 'N/A')}/{data.get('transport', 'tcp')} {Fore.LIGHTMAGENTA_EX}| {Fore.CYAN}Product: {Fore.YELLOW}{product}{Fore.RESET}")
		output.append(f"{Fore.WHITE}[{Fore.CYAN}*{Fore.WHITE}] {Fore.CYAN}TimeStamp: {Fore.YELLOW}{final_date}{Fore.RESET}")
		return output

	return []
	
def search_ip(api: shodan.Shodan, ip: str, mode: str = "interactive") -> None:
	try:
		result = api.host(ip)
		if not result:
			print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}No results found for IP: {Fore.YELLOW}{ip}{Fore.RESET}\n")
			return
		print(f"\n{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Results for IP: {Fore.YELLOW}{ip}{Fore.RESET}\n")
		output = format_output("ip", result, mode)
		for line in output:
			print(line)
			
		print()
	except shodan.APIError as e:
		print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}API Error: {e}{Fore.RESET}\n")
		if mode == "interactive":
			input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Press Enter to return to the menu...')}{Fore.RESET}")
		else:
			exit(1)
	except Exception as e:
		print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Error: {e}{Fore.RESET}\n")

def query_search(api: shodan.Shodan, query: str, mode: str = "interactive") -> None:
	if mode == "interactive":
		page = 1
		while True:
			try:
				clear(); banner()
				results = api.search(query, page=page)
				if not results or results.get('total', 0) == 0:
					print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}No results found for query: {Fore.YELLOW}{query}{Fore.RESET}\n")
					return
				
				total_pages = math.ceil(results.get('total', 0) / 100)
				print(f"{Fore.WHITE}[{Fore.BLUE}*{Fore.WHITE}] {Fore.BLUE}Searching for: {Fore.YELLOW}{query} {Fore.WHITE}(Page {page} of {total_pages})...")

				
				print(f"\n{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Total results for query '{rainbow(query)}{Fore.GREEN}': {Fore.YELLOW}{results.get('total', 0)}{Fore.RESET}\n")
				
				for match in results.get('matches', []):
					print(f"{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{'-'*40}{Fore.WHITE}]")
					output = format_output("query", match)
					for line in output:
						print(line)
					print(f"{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{'-'*40}{Fore.WHITE}]\n")

				print(f"{Fore.CYAN}Navigation: {Fore.WHITE}[{Fore.YELLOW}n{Fore.WHITE}] Next | [{Fore.YELLOW}p{Fore.WHITE}] Previous | [{Fore.YELLOW}q{Fore.WHITE}] Quit to menu | [{Fore.YELLOW}1-{total_pages}{Fore.WHITE}] Jump to page\n")
				choice = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Select option:')} {Fore.RESET}").lower().strip()
				if choice == 'q':
					break

				elif choice == 'n':
					if page < total_pages:
						page += 1
					else:
						print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}You are already on the last page.{Fore.RESET}\n")
						time.sleep(1)
				
				elif choice == 'p':
					if page > 1:
						page -= 1
					else:
						print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}You are already on the first page.{Fore.RESET}\n")
						time.sleep(1)
				
				elif choice.isdigit() and 1 <= int(choice) <= total_pages:
					page = int(choice)

				else:
					print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Invalid option selected.{Fore.RESET}\n")
					time.sleep(1)

			except shodan.APIError as e:
				error = str(e).lower()

				if "search cursor timed out" in error:
					print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Search cursor timed out. Returning to the first page.{Fore.RESET}\n")
					page = 1
					time.sleep(1)
					continue

				print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}API Error: {e}{Fore.RESET}\n")
				return
			
			except Exception as e:
				print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Error: {e}{Fore.RESET}\n")

			except KeyboardInterrupt:
				break
	else:
		try:
			results = api.search(query)
			if not results or results.get('total', 0) == 0:
				print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}No results found for query: {Fore.YELLOW}{query}{Fore.RESET}\n")
				return
			
			print(f"{Fore.WHITE}[{Fore.BLUE}*{Fore.WHITE}] {Fore.BLUE}Searching for: {Fore.YELLOW}{query}{Fore.RESET}")

			print(f"\n{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Total results for query '{rainbow(query)}{Fore.GREEN}': {Fore.YELLOW}{results.get('total', 0)}{Fore.RESET}\n")
			
			for match in results.get('matches', []):
				print(f"{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{'-'*40}{Fore.WHITE}]")
				output = format_output("query", match)
				for line in output:
					print(line)
				print(f"{Fore.WHITE}[{Fore.LIGHTMAGENTA_EX}{'-'*40}{Fore.WHITE}]\n")

		except shodan.APIError as e:
			print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}API Error: {e}{Fore.RESET}\n")
		except Exception as e:
			print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Error: {e}{Fore.RESET}\n")

def setup() -> str:
	"""Configura la clave de API de Shodan para su uso en la aplicación."""
	clear(); banner()

	txt = rainbow('Checking for API key')
	for char in ["/", "-", "\\", "|", "/", "-", "\\", "|", "#"]:
		print(f"\r{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {txt} {Fore.YELLOW}{char}{Fore.RESET}", end="")
		time.sleep(0.2)
	print()

	key = read_env()

	if key and check_key(key):
		print(f"{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Valid API key found.{Fore.RESET}")
		time.sleep(.7)
		return key
		
	if not key:
		print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}No API key found in {Fore.YELLOW}.env {Fore.RED}file.")
	else:
		print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}The API key in {Fore.YELLOW}.env {Fore.RED}file is invalid.")
		 
	print(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Get your API key from')} {Fore.YELLOW}https://account.shodan.io/{Fore.LIGHTCYAN_EX}", end="\n\n")

	while True:
		key_inp = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Enter your Shodan API key:')} {Fore.RESET}").strip()
		if check_key(key_inp):
			print(f"{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Valid API key found.{Fore.RESET}")
			try:
				with open(".env","w") as f:
					f.write(f"SHODAN_KEY={key_inp}")
				print(f"\n{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}API key saved to {Fore.YELLOW}.env{Fore.GREEN} file successfully.{Fore.RESET}\n")
			except IOError:
				print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Failed to save API key to {Fore.YELLOW}.env{Fore.RED} file.{Fore.RESET}\n")
			
			return key_inp
		else:
			print(f"\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Invalid API key.")
	
def menu(api: shodan.Shodan) -> None:
	while True:
		clear(); banner()
		print(f"{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]{rainbow('-'*31)}{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]")
		print(f"""
    {Fore.WHITE}[{Fore.BLUE}1{Fore.WHITE}] {rainbow('Search by IP address')} 🌐
    {Fore.WHITE}[{Fore.BLUE}2{Fore.WHITE}] {rainbow('Search by query')} 🔎
    {Fore.WHITE}[{Fore.BLUE}0{Fore.WHITE}] {rainbow('Exit')} ❌
		""")
		print(f"{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]{rainbow('-'*31)}{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]\n")

		choice = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Select an option:')} {Fore.RESET}").strip()
		print()

		if choice == "1":
			ip = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Enter IP address:')} {Fore.RESET}").strip()
			clear(); banner()
			search_ip(api, ip)
			print()
			input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Press Enter to return to the menu...')}{Fore.RESET}")
		elif choice == "2":
			query = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Enter search query:')} {Fore.RESET}").strip()
			clear(); banner()
			query_search(api, query)
			print()
			input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Press Enter to return to the menu...')}{Fore.RESET}")
		elif choice == "0":
			print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Exiting...{Fore.RESET}\n")
			time.sleep(.7)
			clear()
			exit()
		else:
			print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Invalid option selected.{Fore.RESET}\n")
			time.sleep(1)

if __name__ == "__main__":
	try:
		parser = argparse.ArgumentParser(description="ShodanLookUp Tool")
		parser.add_argument('-m', '--mode', choices=['ip', 'query'], help='Mode of operation: ip for IP search, query for query search', type=str)
		parser.add_argument('-t', '--target', help='Target IP address or query string based on the selected mode', type=str)
		
		args = parser.parse_args()

		if args.mode and args.target:
			api_key = read_env()
			if not api_key or not check_key(api_key):
				print(f"{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Valid API key not found. Please run the script without arguments to set up the API key.{Fore.RESET}\n")
				exit()
			api = shodan.Shodan(api_key)
			if args.mode == 'ip':
				search_ip(api, args.target, mode="cli")
			elif args.mode == 'query':
				query_search(api, args.target, mode="cli")
			exit()

		api_key = setup()
		menu(shodan.Shodan(api_key))
	except KeyboardInterrupt:
		print(f"\n\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Detected {Fore.YELLOW}keyboard interrupt. {Fore.RED}Exiting...{Fore.RESET}")
		time.sleep(.7)
		clear()
		exit()