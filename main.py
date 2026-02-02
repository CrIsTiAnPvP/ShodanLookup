#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports
import os, shodan, time
from rainbow import *
from colorama import Fore


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

def format_output(label: str, data: str) -> str:
	return f"{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.CYAN}{label}: {Fore.YELLOW}{data}{Fore.RESET}"

def search_ip(api: shodan.Shodan, ip: str) -> None:
	try:
		result = api.host(ip)
		print(f"\n{Fore.WHITE}[{Fore.GREEN}+{Fore.WHITE}] {Fore.GREEN}Results for IP: {Fore.YELLOW}{ip}{Fore.RESET}\n")
		for key, value in result.items():
			print(format_output(key, str(value)))
			
		print()
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
		time.sleep(0.3)
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
	clear(); banner()
	print(f"{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]{rainbow('-'*31)}{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]")
	print(f"""
    {Fore.WHITE}[{Fore.BLUE}1{Fore.WHITE}] {rainbow('Search by IP address')} 🌐
    {Fore.WHITE}[{Fore.BLUE}2{Fore.WHITE}] {rainbow('Search by Domain name')} 🏷️
    {Fore.WHITE}[{Fore.BLUE}3{Fore.WHITE}] {rainbow('Search by query')} 🔎
    {Fore.WHITE}[{Fore.BLUE}0{Fore.WHITE}] {rainbow('Exit')} ❌
	""")
	print(f"{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]{rainbow('-'*31)}{Fore.WHITE}[{Fore.BLUE}+{Fore.WHITE}]")

	print(api.info())

	choice = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Select an option:')} {Fore.RESET}").strip()


	if choice == "1":
		ip = input(f"{Fore.WHITE}[{Fore.BLUE}?{Fore.WHITE}] {rainbow('Enter IP address:')} {Fore.RESET}").strip()
		search_ip(api, ip)




if __name__ == "__main__":
	try:
		api_key = setup()
		menu(shodan.Shodan(api_key))
	except KeyboardInterrupt:
		print(f"\n\n{Fore.WHITE}[{Fore.RED}!{Fore.WHITE}] {Fore.RED}Detected {Fore.YELLOW}keyboard interrupt. {Fore.RED}Exiting...{Fore.RESET}")
		time.sleep(.7)
		clear()
		exit()