# -*- coding: utf-8 -*-
'''
   _____                     __    ______          __
  / ___/____  ___  ___  ____/ /   /_  __/__  _____/ /_
  \__ \/ __ \/ _ \/ _ \/ __  /_____/ / / _ \/ ___/ __/
 ___/ / /_/ /  __/  __/ /_/ /_____/ / /  __(__  ) /_
/____/ .___/\___/\___/\__,_/     /_/  \___/____/\__/
    /_/
'''
#######################################################
#    Speed-Test.py
#
# Speed-Test is a utility that allows you to diagnose 
# network problems, monitor bandwidth and scan devices
#  on a local network. This tool was developed in 
# Python to provide information about connectivity 
# and devices within a network.
#
#
# 11/09/23 - Changed to Python3 (finally)
#
# Author: Facundo Fernandez 
#
#
#######################################################

import os
import subprocess
import nmap
import socket
from scapy.all import ARP, Ether, srp

def test_internet():
    os.system('speedtest-cli')

def monitor_bandwidth():
    process = subprocess.Popen(['sudo', 'iftop', '-t', '-s', '1'], stdout=subprocess.PIPE)
    while True:
        output = process.stdout.readline()
        if output == b'':
            break
        print(output.strip().decode('utf-8'))

def run_command(command):
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output, error

def diagnose_network():
    traceroute_output, _ = run_command("traceroute 8.8.8.8")  # Uses an external IP address as an example / Utiliza una dirección IP externa como ejemplo

    tcpdump_output, _ = run_command("sudo tcpdump -c 10 -i eth0")  # Change 'eth0' to your network interface / Cambia 'eth0' por tu interfaz de red

    return traceroute_output, tcpdump_output

def arp_scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet layer for the frame / Capa Ethernet para la trama
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]  # Sends the frame and receives responses / Envía la trama y recibe respuestas

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_device_names(ip_addresses):
    device_names = {}
    for ip in ip_addresses:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            device_names[ip] = hostname
        except socket.herror:
            device_names[ip] = "Unknown"
    return device_names

if __name__ == "__main__":
    test_internet()  
    monitor_bandwidth()  

    traceroute, tcpdump = diagnose_network() 
    print("Traceroute output:")
    print(traceroute.decode('utf-8'))

    print("\nTcpdump output:")
    print(tcpdump.decode('utf-8'))

    local_devices = arp_scan("192.168.1.0/24")

    ip_addresses = [device['ip'] for device in local_devices]

    device_names = get_device_names(ip_addresses)

    # Assign the names found to each device / Asignar los nombres encontrados a cada dispositivo
    for device in local_devices:
        device['name'] = device_names.get(device['ip'], "Unknown")

    # Display the found devices with their respective names / Mostrar los dispositivos encontrados con sus respectivos nombres
    print("Devices in the local network:")
    for device in local_devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Name: {device['name']}")
