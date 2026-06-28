# Wazuh SIEM &amp; Detection Engineering Lab

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)](https://attack.mitre.org/)

## 📝 Project Overview
This repository contains architecture diagrams, configuration files, and implementation details of the **Centralized Network Security Monitoring &amp; Incident Response System** built on the **Wazuh SIEM/XDR** platform. Designed to simulate a real enterprise operating environment, this project focuses on log collection, custom attack detection rules (**Detection Engineering**) standardized according to the **MITRE ATT&amp;CK** framework, automated defense (**Active Response**), and real-time alert triggering.

### Core Objectives:
*   Deploy a stable SIEM/XDR infrastructure using open-source tools.
*   Configure in-depth endpoint auditing via **Windows Sysmon** and system logs.
*   Build **Custom Decoders and Rules** to detect sophisticated attack techniques.
*   Implement proactive defense mechanisms with **Active Response** to automatically block ongoing threats.
*   Integrate real-time alert system to centralized monitoring channels (Telegram/Discord).

---

## 🏗️ Architecture &amp; Lab Setup

### Data Flow &amp; Network Topology
```text
  [ Kali Linux (Attacker) ] --(Attack)--&gt; [ Windows 10 (Victim) ]
                                                            │
                                                    (Sysmon / Event Logs)
                                                            │
                                                            ▼
                                                   [ Wazuh Agent ]
                                                            │
                                                   (Send encrypted logs)
                                                            │
                                                            ▼
                                            [ Ubuntu Server (Wazuh Manager) ]
                                               ├── Wazuh Indexer (Log storage)
                                               └── Wazuh Dashboard (Web interface)
                                                            │
                                                   (Trigger alerts)
                                                            │
                                                            ▼
                                                 [ Telegram/Discord Bot ]

```

&gt; 💡 *Tip: You can replace this text block with a network diagram from Draw.io/Figma and save it in the `architecture/topology.png` directory.*

### Component Specifications:

1. **Wazuh Manager (Running on Ubuntu Server):** Serves as the central hub responsible for log decoding, rule matching, alert triggering, and automatic incident response commands.
2. **Endpoint Monitoring (Windows 10 Machine):** Installed with **Wazuh Agent** paired with **Microsoft Sysmon** (using an advanced security configuration file) to capture all kernel-level and system process behaviors.
3. **Attack Platform (Kali Linux Machine):** Used to simulate hacker attack techniques targeting Windows 10 to generate test logs.

---

## 🗂️ Repository Structure

```text
wazuh-soc-lab/
│
├── README.md               # Main documentation: Diagrams, setup guide, results (Most important)
├── documents/              # Theoretical documentation
│
├── architecture/           # Contains network diagrams, log flow diagrams (drawn with Draw.io/Figma)
│
├── deployment/             # Installation guides or scripts
│   ├── docker-compose.yml  # (If deploying Wazuh with Docker)
│   └── sysmon-config.xml   # Optimized Sysmon configuration file (like SwiftOnSecurity) to load on Windows
│
├── custom-rules/           # SHOWCASE: Contains custom XML rules you wrote
│   ├── web-lfi-detection.xml
│   ├── ssh-brute-force-active-response.xml
│   └── sysmon-powershell-rules.xml
│
├── integrations/           # Alert integration code
│   └── ossec-slack-telegram.js / python # Script to push alerts to Telegram/Discord
│
└── reports/                # PDF files reporting a specific case study from this lab
```

---

## 🚀 Attack Scenarios &amp; Real-World Detection (Key Use Cases)

### 🔹 Scenario 1: T1110 - Detect Brute Force Attack &amp; Auto-block IP (Active Response)

* **Attacker Behavior:** Use `Hydra` tool from Kali Linux to perform high-speed password guessing via RDP/SSH protocols targeting the victim machine.
* **Telemetry (Log) Collection:** Monitor system login logs from the operating system (Windows Event ID 4625 - Failed login).
* **Detection Strategy:** Build a custom-designed Rule to detect consecutive failed login attempts exceeding the configured threshold from the same source IP within a 10-second time window.
* **Mitigation Response (Active Response):** Trigger an automatic firewall script on the management system to drop all incoming packets from the Kali Linux IP for 600 seconds (10 minutes).
* **Practical Proof (PoC):**
&gt; *[Insert screenshot of Wazuh Dashboard showing Rule triggered &amp; Active Response executed successfully]*



### 🔹 Scenario 2: T1210 - Exploit Web Application Vulnerability (Local File Inclusion - LFI)

* **Attacker Behavior:** Perform directory traversal technique and LFI attack targeting a simulated Web Server service running on the victim machine, attempting to read sensitive system files (like `..\..\boot.ini` or configuration files).
* **Telemetry (Log) Collection:** Configure Wazuh to collect and read access logs from the Web service (Apache/Nginx/IIS).
* **Detection Strategy:** Design custom **Decoders** and **Rules** using regular expressions (`Regex`) to parse the URI field, identify characteristic malicious character sequences (`..%2f`, `%00`, `boot.ini`). Raise alert severity to Level 10 (High).
* **Practical Proof (PoC):**
&gt; *[Insert screenshot of Security Events in Wazuh showing exactly the malicious URI captured and flagged]*



### 🔹 Scenario 3: T1059.001 - Detect Malicious PowerShell Execution &amp; Process Monitoring

* **Attacker Behavior:** Launch an obfuscated PowerShell script to perform LSASS memory dumping for credential theft or internal information reconnaissance (Using anonymous parameters like Base64).
* **Telemetry (Log) Collection:** Use advanced logs from **Windows Sysmon Event ID 1 (Process Creation)** and **Event ID 7 (Image Loaded)**.
* **Detection Strategy:** Configure a rule set directly matching dangerous PowerShell command-line parameters (e.g., `-EncodedCommand`, `-WindowStyle Hidden`, `-NoP`).
* **Practical Proof (PoC):**
&gt; *[Insert screenshot of detailed Sysmon log analyzing the parent process and Wazuh flagging the obfuscated command]*



---

## 🤖 SOAR Integration: Alert System via Chat Channels (ChatOps)

To optimize response time and minimize alert fatigue (Alert Fatigue), this lab integrates a customizable webhook script located at (`integrations/wazuh-telegram-alert.py`).

Whenever the system generates an alert with **Severity Level ≥ 10**, Wazuh Manager will forward the alert's JSON metadata to the Python script to reformat and immediately push an emergency notification to the dedicated SOC chat channel.

### Visual Alert Template:

```json
⚠️ [SOC ALERT] DETECTED SEVERE SECURITY INCIDENT
● Rule ID: 100201 (Custom LFI Detection)
● Severity Level: 10 (High)
● Endpoint: Windows10-User (002)
● Attacker IP: 192.168.X.X
● Detailed Description: Detected suspicious Local File Inclusion attack on target URI.

```

&gt; *[Insert screenshot of actual notification message received on Telegram or Discord]*

---

## 🛠️ Installation &amp; Deployment Guide

### 1. Prerequisites

* Virtualization software: VMware Workstation or VirtualBox.
* Recommended hardware resources: Allocate at least 8GB RAM for the Ubuntu Server VM (running Wazuh Stack cluster) and 2GB RAM for the Windows 10 VM.

### 2. Deploy Wazuh Stack Cluster

```bash
# Clone project source code to your machine
git clone [https://github.com/tofan0810/Wazuh-SOC-lab](https://github.com/tofan0810/Wazuh-SOC-lab)
cd Wazuh-SOC-lab/deployment

# Launch SIEM system cluster with Docker Compose
docker-compose up -d
```

### 3. Configure on Target Endpoint

* Download and install Wazuh Agent on Windows 10, point configuration IP to the Ubuntu machine (Wazuh Manager).
* **Advanced Windows Configuration:** Install Microsoft Sysmon using the configuration file included in the source code bundle:

```cmd
    sysmon.exe -i sysmon-config.xml
```
*   **Update Custom Detection Rules:** Copy all files in the `custom-rules/` directory to the path `/var/ossec/etc/rules/` on the Ubuntu Manager machine, then restart the wazuh-manager service.

---

## 📊 Practical Skills Gained Through This Project
*   **SIEM/XDR Administration &amp; Operations:** Master system architecture, agent component installation, optimize incoming log sources.
*   **Attack Detection Engineering:** Proficiency in writing rules with XML structure, designing decoder filters, using regular expressions (Regex), and optimizing to minimize false positives.
*   **Endpoint Telemetry Analysis:** Deep understanding of Windows Event Logs logging mechanism, advanced Sysmon data table structure.
*   **Automation &amp; Incident Response:** Trigger proactive isolation scripts via Active Response and configure automated notification data flows (Webhook Notification Flows).
