# DHCP Spoofing and Starvation Attack

This project implements a hybrid network attack combining DHCP starvation and DHCP spoofing to gain control of network clients.

## Attack Description
The attack has two phases:
1. **DHCP Starvation**: Flood the legitimate DHCP server with requests to exhaust its IP pool
2. **DHCP Spoofing**: Respond to client requests with malicious configuration (gateway/DNS)

## Requirements
- Python 3.6+
- Scapy
- Root/Administrator privileges

## Installation
```bash
pip install -r requirements.txt
