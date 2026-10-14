# 🛡️ Wazuh Manager, NIDS & SOAR Provisioning Package (Ubuntu Server)

This package comprehensively bundles container configurations, SIEM rulesets, Suricata NIDS, and SOAR orchestration workflows for **Ubuntu Server 22.04 LTS (`192.168.71.128`)**.

---

## ⚡ 2-STEP DEPLOYMENT GUIDE (QUICKSTART)

### Step 1: Install Foundational Prerequisites (Pre-installed by User)
On a fresh Ubuntu Server host, open a terminal and execute the command to install required system packages:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin suricata jq python3-pip
```

---

### Step 2: Run Master Setup Script (1-Click Setup)
Navigate to the `manager/` directory and execute:

```bash
chmod +x setup_manager.sh
sudo ./setup_manager.sh
```

**The `setup_manager.sh` script automatically executes 100% of remaining tasks:**
1. ✅ Adjusts Kernel parameters automatically: `sysctl -w vm.max_map_count=262144` and persists to `/etc/sysctl.conf` (ensuring Wazuh Indexer / OpenSearch operates without memory crashes).
2. ✅ Starts Docker containers for Wazuh SIEM All-in-One (Manager, Indexer, Dashboard) and n8n SOAR (Port 5678).
3. ✅ Injects custom ruleset `rules/local_rules.xml` (Rules 100001 - 100016), `rules/local_decoder.xml`, and script `soar/custom-n8n.py` directly into the Wazuh Manager container.
4. ✅ Enables Suricata 8.x NIDS on network interface `ens33` (Promiscuous mode) and configures streaming of `eve.json` logs into Wazuh.
5. ✅ Launches the background daemon `soar/telegram_bridge.py` to handle callback queries from Telegram ChatOps buttons.
6. ✅ Outputs Dashboard and n8n management access URLs.

*After containers complete startup initialization (~1 minute), import the Executive Dashboard using:*
```bash
python3 dashboard/import_dashboard.py
```

---

## 🗂️ Directory Structure: `manager/`

```text
manager/
├── README.md                      # Ubuntu SIEM/SOAR server deployment guide
├── setup_manager.sh               # Master 1-Click automation script for the host
├── docker/
│   ├── docker-compose.yml         # Wazuh Manager, Indexer, Dashboard stack (Port 443)
│   ├── docker-compose-n8n.yml     # n8n Automation Engine container (Port 5678)
│   ├── ossec.conf                 # Central Wazuh Manager configuration & Webhook integration
│   └── .env.example               # Safe API keys configuration template (Zero Secret Leakage)
├── rules/
│   ├── local_rules.xml            # Compiled production Wazuh XML rules (Rules 100001 - 100016)
│   ├── local_decoder.xml          # Custom decoder for Apache Web Access Logs
│   ├── sigma/                     # Sigma YAML SSOT rule repository (9 detection rules)
│   └── README.md                  # Detection-as-Code ruleset management guide
├── suricata/
│   ├── suricata.yaml              # Packet capture on ens33 & eve.json streaming config
│   ├── local.rules                # 4 NIDS Signatures (Nmap SYN, LFI, Scanners, RDP)
│   └── setup_suricata.sh          # Network adapter tuning & Suricata service setup script
├── soar/
│   ├── workflows/                 # 3 standardized n8n workflow JSON templates
│   ├── custom-n8n.py              # IoC extraction & alert dispatch script to n8n
│   ├── telegram_bridge.py         # Long-polling daemon handling WinRM interactive callbacks
│   └── restart_bridge.sh          # Helper script to restart bridge daemon
└── dashboard/
    ├── soc_lab_executive_dashboard.ndjson # 7 professional OpenSearch Visualizations
    └── import_dashboard.py                # 1-click import script via OpenSearch REST API
```
