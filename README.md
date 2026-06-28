# Wazuh SIEM & Detection Engineering Lab

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)](https://attack.mitre.org/)

## 📝 Project Overview

This repository contains architecture diagrams, configuration files, and deployment details of a **Centralized Network Security Monitoring & Incident Response System** built on the **Wazuh SIEM/XDR** platform. Designed to simulate a real enterprise operational environment, this project focuses deeply on log collection, custom attack detection rule authoring (**Detection Engineering**) standardized according to the **MITRE ATT&CK** framework, defense automation (**Active Response**), and real-time alert triggering.

### Core Objectives:
*   Deploy a stable SIEM/XDR infrastructure using open-source tools.
*   Configure in-depth endpoint auditing via **Windows Sysmon** and system logs.
*   Build **Custom Decoders and Rules** to detect sophisticated attack techniques.
*   Deploy an **Active Response** proactive defense mechanism to automatically block ongoing threats.
*   Integrate real-time alerting to a centralized monitoring channel (Telegram/Discord) **(To be researched and developed in the future)**.

---

## 🏗️ Lab Architecture & Setup

### Topology Model and Data Flow
```text
                   ┌─────────────────────┐
                   │ Kali Linux          │
                   │ Attacker            │  
                   │ (IP: 192.168.71.130)│
                   └───────┬─────────────┘
                           │
                           │ Attack
                           ▼
                   ┌──────────────────────┐
                   │ Windows 10           │
                   │ Wazuh Agent          │
                   │ (IP: 192.168.71.129) │
                   └───────┬──────────────┘
                           │
                           │ Logs (Sysmon/Security/Apache)
                           ▼
                   ┌─────────────────────────────┐
                   │ Ubuntu Server (Wazuh Manager) │
                   │ Docker Single-Node            │
                   │ (IP: 192.168.71.128)          │
                   ├── Wazuh Indexer (Log Storage) │
                   └── Wazuh Dashboard (UI)        │
                           │
                           │ Alerts
                           ▼
                   ┌─────────────────┐
                   │ Wazuh           │
                   │ Dashboard       │
                   └─────────────────┘
```

> 💡 **Note:** Detailed deployment steps are documented in the reports located in the `reports/` directory.

### Component Technical Specifications:
1. **Wazuh Manager (Running on Ubuntu Server 22.04/24.04):**
   - Acts as the central hub responsible for log decoding, rule matching, alert triggering, and issuing automated response commands.
   - Deployed via Docker Compose (Single-Node Architecture).
   - Configured with admin password changes, container log limits, and kernel hardening (vm.max_map_count=262144).
2. **Endpoint Monitoring (Windows 10 Pro Machine):**
   - Installed with **Wazuh Agent 4.14.5** in conjunction with **Microsoft Sysmon v15.2** (using a custom configuration file) to capture behaviors at the kernel and system process level.
   - Configured with log_alert_level=0 to collect all logs.
3. **Attack Platform (Kali Linux Machine):**
   - Used to simulate hacker attack techniques targeting the Windows 10 machine in order to generate test logs.

---

## 🗂️ Repository Directory Structure

```text
wazuh-soc-lab/
│
├── README.md               # Main documentation
├── documents/              # Theoretical documentation and common commands
│
├── architecture/           # Contains network diagram images (if any)
│
├── deployment/             # Installation guides or scripts
│   ├── docker-compose.yml  # (If Wazuh is deployed with Docker)
│   └── sysmon-config.xml   # Optimized Sysmon configuration file
│
├── custom-rules/           # SHOWCASE: Contains custom XML rules written from scratch
│   ├── (Contains local_rules.xml and local_decoder.xml files)
│
├── integrations/           # Alert integration code **(To be developed in the future)**
│
└── reports/                # Detailed deployment phase reports
    ├── Phase-1_Infrastructure-Deployment.md
    ├── Phase-2_Agent-Sysmon-Configuration.md
    ├── Phase-3_Scenario-1.md
    ├── Phase-3_Scenario-2.md
    └── images/
```

---

## 🚀 Attack & Detection Scenarios in Practice (Successfully Deployed)

### 🔹 Scenario 1: T1110 - RDP BRUTE FORCE ATTACK DETECTION & AUTOMATIC IP BLOCKING (ACTIVE RESPONSE)
* **Attack Model:** Using `xfreerdp` from the Kali Linux machine to perform high-speed password scanning via the RDP protocol.
* **Telemetry Collection (Logs):** Monitoring Windows system login logs — Event ID 4625 (Failed Login).
* **Detection Strategy:** Custom Rule ID 100001 (Level 12) detects multiple consecutive failed login attempts.
* **Mitigation Response (Active Response):** Automatically invokes `netsh` command on the Windows Agent to block the attacker's IP for 600 seconds (10 minutes).
* **Proof of Concept (PoC):** See details at `reports/Phase-3_Scenario-1.md`.


### 🔹 Scenario 2: T1190 - WEB APPLICATION EXPLOITATION (LOCAL FILE INCLUSION - LFI / DIRECTORY TRAVERSAL)
* **Attack Model:** Using `curl` from Kali to exploit an LFI vulnerability on a XAMPP Apache application, attempting to read the `win.ini` file.
* **Telemetry Collection (Logs):** Configuring the Wazuh Agent to collect Apache Access Logs.
* **Detection Strategy:** Custom Decoder to parse the URL + Custom Rule ID 100002 (Level 10) to detect malicious strings (`..%2f`, `..%252f`, `win.ini`, `boot.ini`).
* **Mitigation Response (Active Response):** Automatically block the attacker's IP for 600 seconds.
* **Proof of Concept (PoC):** See details at `reports/Phase-3_Scenario-2.md`.


---

## 🤖 SOAR Integration: Alert System via Chat Channel (ChatOps)
> ⚠️ **Note:** This feature **will be researched and developed in the future.** Currently, the system has completed 2 attack and detection scenarios along with an Active Response mechanism.

---

## 🛠️ Installation & Deployment Guide
See detailed steps in the reports inside the `reports/` directory:
1. Deploy the Wazuh Stack infrastructure: `reports/Phase-1_Infrastructure-Deployment.md`
2. Configure Agent and Sysmon: `reports/Phase-2_Agent-Sysmon-Configuration.md`
3. Deploy attack and detection scenarios: `reports/Phase-3_Scenario-1.md` and `reports/Phase-3_Scenario-2.md`

### Prerequisites:
*   Virtualization software: VMware Workstation or VirtualBox.
*   Recommended hardware resources:
  - Ubuntu Server: At least 2 vCPU, 4GB RAM, 65GB SSD.
  - Windows 10: At least 2 vCPU, 2GB RAM.


---

## 📊 Practical Skills Gained Through This Project
*   **SIEM/XDR Administration & Operations:** Solid understanding of system architecture, Agent subsystem installation, and log source ingestion optimization.
*   **Detection Engineering:** Proficient in writing rules using XML structure, designing decoder filters, using regular expressions (Regex), and thinking strategically to minimize false positives.
*   **Endpoint Telemetry Analysis:** Deep understanding of Windows Event Logs recording mechanisms and the advanced Sysmon data table structure.
*   **Automation & Incident Response:** Triggering proactive isolation scenarios via Active Response and configuring automated notification data flows (Webhook Notification Flows).

---

## 📚 References
- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)