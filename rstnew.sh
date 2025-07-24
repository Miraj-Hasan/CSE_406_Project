#!/bin/bash

IFACE="wlp2s0"
THREADS=50

echo "========================================"
echo "⚠️  FAST DHCP STARVATION ATTACK WARNING"
echo "Interface: $IFACE | Threads: $THREADS"
echo "Target: Entire broadcast domain"
echo "NOTE: This will likely block IPs for ALL new devices"
echo "========================================"
read -p "Are you sure? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
  echo "[*] Cancelled"
  exit 1
fi

sudo $(which python3) new.py -i $IFACE -t $THREADS
