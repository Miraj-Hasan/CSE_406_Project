#!/usr/bin/env python3
from scapy.all import *
import random
import time

def generate_random_mac():
    return "52:54:00:%02x:%02x:%02x" % (
        random.randint(0, 127),
        random.randint(0, 255),
        random.randint(0, 255)
    )

iface = "wlp2s0"  # 🔧 Replace with your interface name
client_mac = generate_random_mac()

transaction_id = random.randint(1, 0xFFFFFFFF)

print(f"[*] Using MAC: {client_mac}")
print(f"[*] Transaction ID: {hex(transaction_id)}")

# Step 1: DHCP DISCOVER
discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac) / \
    IP(src="0.0.0.0", dst="255.255.255.255") / \
    UDP(sport=68, dport=67) / \
    BOOTP(chaddr=mac2str(client_mac), xid=transaction_id, flags=0x8000) / \
    DHCP(options=[("message-type", "discover"), ("end")])

print("[1] Sending DHCP DISCOVER")
sendp(discover, iface=iface, verbose=0)

# Step 2: Wait for DHCP OFFER
print("[2] Waiting for DHCPOFFER...")
offer = sniff(filter="udp and (port 67 or 68)", iface=iface, timeout=5, count=1,
              lfilter=lambda p: DHCP in p and p[DHCP].options[0][1] == 2)

if not offer:
    print("[!] No DHCPOFFER received")
    exit(1)

offer_pkt = offer[0]
offered_ip = offer_pkt[BOOTP].yiaddr
server_ip = offer_pkt[IP].src
server_mac = offer_pkt[Ether].src
print(f"[+] Got OFFER of IP {offered_ip} from server {server_ip} ({server_mac})")

# Step 3: DHCP REQUEST
request = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / \
    IP(src="0.0.0.0", dst="255.255.255.255") / \
    UDP(sport=68, dport=67) / \
    BOOTP(chaddr=mac2str(client_mac), xid=transaction_id, flags=0x8000) / \
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", offered_ip),
        ("server_id", server_ip),
        ("end")
    ])

print("[3] Sending DHCP REQUEST")
sendp(request, iface=iface, verbose=0)

# Step 4: Wait for DHCP ACK
print("[4] Waiting for DHCPACK...")
ack = sniff(filter="udp and (port 67 or 68)", iface=iface, timeout=5, count=1,
            lfilter=lambda p: DHCP in p and p[DHCP].options[0][1] == 5)

if ack:
    print(f"[+] 🎉 DHCPACK received. IP {offered_ip} is now yours!")
else:
    print("[!] No DHCPACK received")
