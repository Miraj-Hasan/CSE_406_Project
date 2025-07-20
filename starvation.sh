#!/bin/bash
sudo $(which python) dhcp_starvation.py -i wlp2s0 -s 192.168.1.1 -n 192.168.1.0/24 -t 50 -d 300
