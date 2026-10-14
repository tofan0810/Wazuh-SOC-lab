#!/usr/bin/env bash
# ==============================================================================
# 1-Click Automated Suricata NIDS Setup Script for SOC Lab (Ubuntu VM 192.168.71.128)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  🚀 DEPLOYING SURICATA NIDS 7.x - SOC LAB XDR INTEGRATION     ${NC}"
echo -e "${BLUE}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root (use sudo).${NC}"
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Detect Network Interface (default ens33 for VMware, fallback to default route)
TARGET_IFACE="ens33"
if ! ip link show "$TARGET_IFACE" > /dev/null 2>&1; then
    TARGET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    echo -e "${YELLOW}[*] 'ens33' not found, automatically selected active interface: ${TARGET_IFACE}${NC}"
else
    echo -e "${GREEN}[+] Target network interface: ${TARGET_IFACE}${NC}"
fi

# 2. Add Suricata Official PPA & Install Packages
echo -e "${BLUE}[*] Step 1: Installing Suricata & Tools...${NC}"
apt-get update -y
apt-get install -y software-properties-common jq ethtool curl
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata

# 3. Configure Network Interface Offloads & Promiscuous Mode
echo -e "${BLUE}[*] Step 2: Optimizing Network Interface for Packet Capture...${NC}"
ip link set "$TARGET_IFACE" promisc on || true
ethtool -K "$TARGET_IFACE" gro off lro off rx off tx off || true
echo -e "${GREEN}[+] Promiscuous mode enabled on ${TARGET_IFACE}.${NC}"

# 4. Deploy Custom Configuration & Signatures
echo -e "${BLUE}[*] Step 3: Deploying Suricata Configurations & Signatures...${NC}"
mkdir -p /etc/suricata/rules
mkdir -p /var/log/suricata

if [[ -f /etc/suricata/suricata.yaml ]]; then
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
fi

# Copy suricata.yaml and replace interface placeholder if needed
cp "${SCRIPT_DIR}/suricata.yaml" /etc/suricata/suricata.yaml
sed -i "s/interface: ens33/interface: ${TARGET_IFACE}/g" /etc/suricata/suricata.yaml

# Copy custom rules
cp "${SCRIPT_DIR}/local.rules" /etc/suricata/rules/local.rules
echo -e "${GREEN}[+] Deployed /etc/suricata/suricata.yaml and /etc/suricata/rules/local.rules.${NC}"

# 5. Set File Permissions for Wazuh Agent / Logcollector Ingestion
echo -e "${BLUE}[*] Step 4: Setting Permissions for Wazuh Ingestion...${NC}"
touch /var/log/suricata/eve.json
touch /var/log/suricata/fast.log
chmod 755 /var/log/suricata
chmod 644 /var/log/suricata/eve.json
chmod 644 /var/log/suricata/fast.log

# 6. Validate Configuration Syntax
echo -e "${BLUE}[*] Step 5: Testing Suricata Configuration (-T mode)...${NC}"
if suricata -T -c /etc/suricata/suricata.yaml -v; then
    echo -e "${GREEN}[+] Suricata configuration test PASSED!${NC}"
else
    echo -e "${RED}[!] Configuration test FAILED. Please check logs.${NC}"
    exit 1
fi

# 7. Enable and Restart Service
echo -e "${BLUE}[*] Step 6: Starting Suricata Service...${NC}"
systemctl daemon-reload
systemctl enable suricata
systemctl restart suricata

sleep 2

if systemctl is-active --quiet suricata; then
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  ✅ SURICATA NIDS IS SUCCESSFULLY ACTIVE & MONITORING!         ${NC}"
    echo -e "${GREEN}  EVE JSON Stream: /var/log/suricata/eve.json                    ${NC}"
    echo -e "${GREEN}  Interface: ${TARGET_IFACE}                                     ${NC}"
    echo -e "${GREEN}================================================================${NC}"
else
    echo -e "${RED}[!] Suricata service failed to start. Check 'journalctl -u suricata -n 50'.${NC}"
    exit 1
fi
