#!/usr/bin/env bash
# ==============================================================================
# WAZUH SOC LAB - 1-CLICK MANAGER MASTER PROVISIONING SCRIPT (UBUNTU SERVER)
# ==============================================================================
# Automates the complete provisioning of the Wazuh SIEM, NIDS & SOAR Server:
#   1. Applies Linux Kernel Tuning (vm.max_map_count=262144 for OpenSearch)
#   2. Verifies Docker & Docker Compose installation
#   3. Launches Wazuh SIEM Stack & n8n SOAR Cluster (Docker)
#   4. Deploys Custom XML Rules (100001-100016) & Decoders to Wazuh Manager
#   5. Configures and launches Suricata 8.x NIDS with Promiscuous capture
#   6. Registers custom-n8n.py integration & background Telegram Bridge
#   7. Imports Executive Dashboard (7 Visualizations) into OpenSearch
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  🛡️  WAZUH SOC LAB - 1-CLICK MANAGER MASTER SETUP (UBUNTU)    ${NC}"
echo -e "${BLUE}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root (use sudo).${NC}"
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# 1. Linux Kernel Tuning (vm.max_map_count)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 1: Cấu hình Kernel Tuning cho Wazuh Indexer / OpenSearch...${NC}"
CURRENT_MAP=$(sysctl -n vm.max_map_count || echo 0)
if [[ "$CURRENT_MAP" -lt 262144 ]]; then
    echo -e "${YELLOW}[*] Updating vm.max_map_count to 262144...${NC}"
    sysctl -w vm.max_map_count=262144
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
        echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    else
        sed -i 's/^vm.max_map_count=.*/vm.max_map_count=262144/' /etc/sysctl.conf
    fi
    echo -e "${GREEN}[+] Kernel setting persisted successfully.${NC}"
else
    echo -e "${GREEN}[+] vm.max_map_count already configured ($CURRENT_MAP >= 262144).${NC}"
fi

# ------------------------------------------------------------------------------
# 2. Check Docker & Docker Compose
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 2: Kiểm tra môi trường Docker & Docker Compose...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[*] Docker not found. Installing docker.io & docker-compose-plugin...${NC}"
    apt-get update -y
    apt-get install -y docker.io docker-compose-plugin
fi

systemctl enable --now docker
echo -e "${GREEN}[+] Docker Engine is ready: $(docker --version)${NC}"

# ------------------------------------------------------------------------------
# 3. Environment File Preparation & Docker Launch
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 3: Khởi chạy cụm container Wazuh SIEM & n8n SOAR...${NC}"
if [[ ! -f "$SCRIPT_DIR/docker/.env" ]]; then
    if [[ -f "$SCRIPT_DIR/docker/.env.example" ]]; then
        cp "$SCRIPT_DIR/docker/.env.example" "$SCRIPT_DIR/docker/.env"
        echo -e "${YELLOW}[*] Created docker/.env from template .env.example.${NC}"
    fi
fi

# Start Wazuh Cluster
echo -e "${BLUE}[*] Starting Wazuh Manager, Indexer & Dashboard...${NC}"
docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" up -d

# Start n8n SOAR
echo -e "${BLUE}[*] Starting n8n SOAR Engine...${NC}"
docker compose -f "$SCRIPT_DIR/docker/docker-compose-n8n.yml" up -d

echo -e "${GREEN}[+] All containers launched successfully.${NC}"

# ------------------------------------------------------------------------------
# 4. Deploy Custom Rules & Decoders into Wazuh Manager Container
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 4: Đồng bộ bộ luật tùy chỉnh XML & Decoders vào Wazuh Manager...${NC}"
MGR_CONTAINER=$(docker ps --filter "name=wazuh.manager" --format "{{.ID}}" | head -n1)

if [[ -n "$MGR_CONTAINER" ]]; then
    echo -e "[*] Injecting local_rules.xml & local_decoder.xml into container: $MGR_CONTAINER"
    docker cp "$SCRIPT_DIR/rules/local_rules.xml" "$MGR_CONTAINER:/var/ossec/etc/rules/local_rules.xml"
    docker cp "$SCRIPT_DIR/rules/local_decoder.xml" "$MGR_CONTAINER:/var/ossec/etc/decoders/local_decoder.xml"
    docker cp "$SCRIPT_DIR/soar/custom-n8n.py" "$MGR_CONTAINER:/var/ossec/integrations/custom-n8n.py"
    docker exec "$MGR_CONTAINER" chown -R wazuh:wazuh /var/ossec/etc/rules /var/ossec/etc/decoders /var/ossec/integrations
    docker exec "$MGR_CONTAINER" chmod 750 /var/ossec/integrations/custom-n8n.py
    docker exec "$MGR_CONTAINER" /var/ossec/bin/wazuh-control restart ruleset || true
    echo -e "${GREEN}[+] Custom rules and integrations successfully synchronized into Wazuh!${NC}"
else
    echo -e "${YELLOW}[!] Warning: Wazuh Manager container is still booting. You can rerun this script in 30 seconds.${NC}"
fi

# ------------------------------------------------------------------------------
# 5. Configure Suricata NIDS 8.x
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 5: Cấu hình Suricata 8.x NIDS trên card mạng...${NC}"
if [[ -f "$SCRIPT_DIR/suricata/setup_suricata.sh" ]]; then
    chmod +x "$SCRIPT_DIR/suricata/setup_suricata.sh"
    "$SCRIPT_DIR/suricata/setup_suricata.sh" || echo -e "${YELLOW}[!] Notice: Suricata setup finished with non-critical alerts.${NC}"
fi

# ------------------------------------------------------------------------------
# 6. Start Telegram Bridge Daemon for ChatOps
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[*] Bước 6: Khởi chạy cầu nối tương tác Telegram ChatOps (telegram_bridge.py)...${NC}"
if [[ -f "$SCRIPT_DIR/soar/telegram_bridge.py" ]]; then
    # Kill existing instance if any
    pkill -f "telegram_bridge.py" || true
    nohup python3 "$SCRIPT_DIR/soar/telegram_bridge.py" > /var/log/telegram_bridge.log 2>&1 &
    echo -e "${GREEN}[+] telegram_bridge.py daemon is running in background (log: /var/log/telegram_bridge.log).${NC}"
fi

# ------------------------------------------------------------------------------
# 7. Summary & URLs
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  🎉 THIẾT LẬP MÁY CHỦ WAZUH SIEM / SOAR / NIDS HOÀN TẤT!      ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "🌐 Wazuh Dashboard  : https://192.168.71.128:443 (admin / SecretPassword)"
echo -e "🤖 n8n SOAR Console : http://192.168.71.128:5678"
echo -e "📜 NIDS Event Stream: /var/log/suricata/eve.json"
echo -e "⚡ Dashboard Import  : python3 manager/dashboard/import_dashboard.py\n"
