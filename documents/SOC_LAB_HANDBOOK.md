# 📘 SOC LAB STUDY HANDBOOK & TECHNICAL SPECIFICATIONS FOR WAZUH SOC & SOAR
> **Systematic Study Handbook & Architecture Notes**  
> **Objective:** Used for notebook study, architecture review, in-depth comprehension of every line of code/config, and confident defense during graduation capstone presentations / SOC & Detection Engineer technical interviews.

---

## 🗂️ NOTEBOOK TABLE OF CONTENTS

* **[Part 1: SOC Architecture Overview & Turnkey Packaging Model](#1-soc-architecture-overview--turnkey-packaging-model)**
* **[Part 2: 6 Refined Core Concepts](#2-6-refined-core-concepts)**
* **[Part 3: System Component Inventory & Roles](#3-system-component-inventory--roles-system-inventory)**
* **[Part 4: Detailed Analysis of Configuration Files & Source Code](#4-detailed-analysis-of-configuration-files--source-code)**
* **[Part 5: Detection Rules Matrix (100001 - 100016)](#5-detection-rules-matrix-100001---100016)**
* **[Part 6: Closed-Loop Incident Response (SOAR Closed-Loop & 1-Click Rollback)](#6-closed-loop-incident-response-soar-closed-loop--1-click-rollback)**
* **[Part 7: 8 Capstone Defense & Technical Interview Q&A (Viva Defense Q&A)](#7-8-capstone-defense--technical-interview-qa-viva-defense-qa)**

---

# 1. SOC ARCHITECTURE OVERVIEW & TURNKEY PACKAGING MODEL

### 1.1. Project Objectives
Build an end-to-end enterprise-grade **Security Operations Center (SOC)** ecosystem delivering full operational battle readiness:
1. **Telemetry Collection:** Capture granular endpoint telemetry from Kernel space (Sysmon v15.2), Windows authentication logs (EVTX), web access logs, and deep network monitoring (Suricata NIDS).
2. **Detection Engineering & DaC:** Manage detection rules using the open Sigma YAML standard (Single Source of Truth - SSOT), automatically compile to Wazuh XML, and enforce zero-drift CI/CD verification.
3. **Threat Intelligence Enrichment:** Automatically query malicious IP reputation via AbuseIPDB API and cross-check suspicious file hashes via VirusTotal Cloud API.
4. **SOAR & Closed-Loop Containment:** Orchestrate **Human-in-the-Loop** incident handling via 2-way Telegram ChatOps, supporting **Isolate/Contain**, **1-Click Rollback**, and automated incident case ticket creation via **Atlassian Jira Cloud REST API v3**.
5. **Deception Defense:** Deploy Canary Honey-files (SACL Event 4663), Honey-accounts (Event 4625), and Decoy Port 21 with **Zero False Positives (0% FP)**, automatically extracting digital forensics evidence (Live DFIR Forensics).

---

### 1.2. Two Turnkey Deployment Packages (`endpoint/` & `manager/`)

The repository is modularized into two turnkey deployment packages, enabling deployment from clean operating systems with a single command:

```text
wazuh-soc-lab/
├── endpoint/                   # 🛡️ VICTIM ENDPOINT PACKAGE (Windows 10 Target - 192.168.71.129)
│   ├── config/                 # ossec.conf (Agent 1514/TCP) & sysmon-config.xml (Sysmon v15.2)
│   ├── active-response/        # kill-process.cmd/ps1 (PID termination) & collect-evidence.cmd/ps1
│   ├── deception/              # setup_canary.ps1 (canary file), network_decoy.ps1/py (decoy port 21)
│   ├── setup_endpoint.ps1      # Master 1-Click script automating entire Windows endpoint configuration
│   └── README.md               # User manual for prerequisite installation & script execution
│
├── manager/                    # 🚀 SIEM & SOAR SERVER PACKAGE (Ubuntu Server - 192.168.71.128)
│   ├── docker/                 # All-in-One Wazuh Stack (Port 443) & n8n SOAR (Port 5678)
│   ├── rules/                  # Sigma YAML SSOT (sigma/), local_rules.xml (100001-100016), local_decoder.xml
│   ├── suricata/               # suricata.yaml (ens33 packet capture), local.rules (4 NIDS signatures)
│   ├── soar/                   # 3 JSON Workflows, custom-n8n.py dispatcher, telegram_bridge.py
│   ├── dashboard/              # soc_lab_executive_dashboard.ndjson (9 OpenSearch visual panels)
│   ├── setup_manager.sh        # Master 1-Click script deploying Docker containers & NIDS
│   └── README.md               # User manual for Docker installation & lab activation
│
├── architecture/               # 16:9 vector SVG system design diagrams
├── commands/                   # Quick reference hub for operational commands
├── documents/                  # Study notes, SIEM theory & lab operational handbook
├── playbooks/                  # 6 Standard Operating Procedures (SOP-01 to SOP-06) based on NIST/SANS
├── reports/                    # Detailed technical experimental reports from Phase 1 to Phase 10
├── scripts/                    # Automation utilities: sync_env.py, sigma_compiler.py, import_dashboard.py
└── tests/                      # 22 CI/CD unit tests (tests/unit/) & E2E verification tests (tests/e2e/)
```

---

### 1.3. End-to-End Pipeline Dataflow Diagram

```text
===================================================================================================
                                END-TO-END SOC PIPELINE DATAFLOW
===================================================================================================

  [ KALI LINUX - 192.168.71.130 ] 
      │ (Attacks: RDP Brute Force, Web LFI, PowerShell Base64, UAC Bypass, LSASS Dump, Nmap Scan)
      ▼
  [ WINDOWS 10 ENDPOINT - 192.168.71.129 ]
      │ • Sysmon v15.2: Process Create (Event 1), LSASS Access (Event 10), Registry Run (Event 12/13)
      │ • Windows Security: RDP Logon Failure (Event 4625), Canary SACL Access (Event 4663)
      │ • Apache HTTP Access Log (access.log) & FTP Decoy Port 21 (Event 60000)
      │ • Wazuh Agent v4.14.5: Forward Telemetry via Port 1514/TCP (AES Encrypted)
      │
      ▼
  [ WAZUH SIEM MANAGER & NIDS - 192.168.71.128 ]
      │ • Suricata NIDS: Capture packets on ens33 -> Log to /var/log/suricata/eve.json
      │ • Wazuh Analysisd Engine: Decoding (local_decoder.xml) & Rule Matching (local_rules.xml)
      │ • Local Active Response: Auto IP block (netsh) or PID termination (kill-process.ps1)
      │
      ├───────────────────────────────┬───────────────────────────────┐
      │ (OpenSearch Port 9200)        │ (<integration> ossec.conf)    │ (<integration> ossec.conf)
      ▼                               ▼                               ▼
  [ Wazuh Indexer & Dashboard ]   [ VirusTotal Cloud API ]     [ custom-n8n.py Dispatcher ]
    (SIEM Visualization Port 443)   (SHA256 Hash Lookup)          (Dual-Mode IOC Resolution)
                                                                      │
                                                                      │ (HTTP POST Webhook JSON)
                                                                      ▼
                                                       [ n8n SOAR ENGINE - Port 5678 ]
                                                           │ (Workflow 1: Threat Enrichment)
                                                           ├─► AbuseIPDB API (IP Lookup)
                                                           ├─► Format Rich HTML Alert Card
                                                           ▼
                                                       [ TELEGRAM CHATOPS BOT ]
                                                           │ (@my_wazuh_soc_alert_bot)
                                                           │ Dispatches interactive card with 3 buttons:
                                                           │ [🚫 Block IP 24h] [🔄 Unblock (Rollback)] [📋 Open Jira]
                                                           │
                                                           │ (Analyst taps button on mobile)
                                                           ▼
                                                       [ telegram_bridge.py ]
                                                           │ (Long-Polling catches callback)
                                                           ▼
                                                       [ n8n Workflow 2: Containment Executor ]
                                                           │
                                    ┌──────────────────────┼──────────────────────┐
                                    ▼                      ▼                      ▼
                           [ Branch action:block ] [ Branch action:unblock ] [ Branch action:jira ]
                                    │                      │                      │
                             Execute WinRM to       Execute WinRM to       Call Jira Cloud API
                             Windows 10 to add      Windows 10 to remove   (POST /rest/api/3/issue)
                             Firewall DROP Rule     Firewall DROP Rule     Create Ticket in KAN
                                    │                      │                      │
                                    └──────────────────────┴──────────────────────┘
                                                           │
                                                           ▼
                                              Confirm result back to Telegram in < 5s
```

---

# 2. 6 REFINED CORE CONCEPTS

### 2.1. Telemetry (Granular Deep-Tier Security Observation)
* **Analogy:** Surveillance cameras monitoring operating system behavior. If the camera is only placed at the front gate (basic Windows Event Log), a burglar rummaging through bedroom cabinets (reading LSASS RAM) goes unnoticed.
* **Mechanism:** Sysmon injects the filter driver `SysmonDrv.sys` directly into the Windows Kernel to intercept and record behaviors before malicious processes can wipe their traces.
* **Key Takeaway:** Default Windows Event Logs **cannot** detect LSASS memory read handles or stealthy registry run key tampering. Sysmon Event 1 (Process Create), Event 10 (ProcessAccess), and Event 12/13 (Registry) are strictly required.

### 2.2. Decoders & Rules (Decoding Engine & Correlation Rules)
* **Analogy:** A Decoder is the **translator** (transforming chaotic raw log lines into clean, labeled data fields). A Rule is the **judge** (evaluating those labeled fields against a legal penal code to issue a verdict).
* **Mechanism:** Raw Log $\rightarrow$ Pre-decoding & Regex Decoding $\rightarrow$ Extract `srcip`, `url`, `eventID` $\rightarrow$ Pass through the Rule Evaluation Tree from Level 0 to 16.
* **Key Takeaway:** A rule with `level="0"` is a **Suppression Rule** — used to suppress false alarms generated by SOAR remediation actions (`socrunner` via WinRM), preventing an infinite alert loop (Feedback Loop).

### 2.3. Active Response vs. SOAR Containment
* **Analogy:** Active Response is an **ABS automatic brake** (the computer halts immediate danger in milliseconds without asking). SOAR is an **incident command center** (the system prepares actionable options, alerting the chief analyst's mobile phone for one-touch confirmation).
* **Technical Comparison:**
  * **Active Response:** Executes locally via the `wazuh-execd` daemon on the Endpoint, providing sub-second reaction to high-confidence threats (such as killing Base64 PowerShell via `kill-process.ps1`).
  * **SOAR (Human-in-the-Loop):** n8n orchestrates across diverse systems (AbuseIPDB, Jira, WinRM, Telegram), handling network isolation decisions that carry business impact risks (preventing accidental denial-of-service on core servers).

### 2.4. Dual-Mode IOC Resolution
* **Analogy:** When attacked from afar, identify and block the external attacker; when a contagious virus breaks out inside the room, isolate the contaminated host immediately to prevent lateral spread.
* **Real-world Problem:** Conventional academic labs only handle network attacks containing `srcip`. When an attacker has gained a foothold and executes local kill chain commands (UAC Bypass, LSASS Dump), the log has no `srcip` $\rightarrow$ SOAR defaults to `Target: N/A` and fails to generate host isolation firewall rules.
* **Proprietary Solution:** The [`manager/soar/custom-n8n.py`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/manager/soar/custom-n8n.py) script dynamically inspects the event:
  * **Mode 1 (Remote Network):** Valid remote `srcip` present $\rightarrow$ Block attacker IP (Kali `192.168.71.130`).
  * **Mode 2 (Host-Internal Kill Chain):** `srcip` is empty $\rightarrow$ Fallback to using the compromised endpoint's own IP (`192.168.71.129`) as the containment target, severing C2 communications.

### 2.5. Safe Host Isolation & 1-Click Rollback (Safe Containment & 5s Rollback)
* **Analogy:** Locking a criminal inside a room without **locking the police out of their master key access door**.
* **Vital Rule:** When creating host isolation firewall rules on Windows (`New-NetFirewallRule -Action Block`), **NEVER BLOCK Port 5985 (WinRM)** and **Port 1514/1515 (Wazuh Agent)**.
* **Significance:** Maintaining management channels allows the SOC Analyst to tap **[🔄 Unblock (Rollback)]** on Telegram to restore endpoint network connectivity within **under 5 seconds** without needing physical console access.

### 2.6. Deception Technology (0% False Positive Active Defense)
* **Analogy:** Placing bait cash bags rigged with alarms in hidden corners. Legitimate family members never touch them; only an intruder actively searching for valuables will touch the bait and trigger the alarm.
* **Mechanism:** Place the Canary honey-file `IT_Admin_Credentials.xlsx` (enabling SACL Audit Event 4663), create a honey-account `backup_admin` (Event 4625), and expose a decoy FTP Port 21 (`network_decoy.ps1`). Any interaction with these assets is **100% malicious intrusion**, immediately triggering automated DFIR digital evidence collection.

---

# 3. SYSTEM COMPONENT INVENTORY & ROLES (SYSTEM INVENTORY)

| No. | Component | Version / Technology | Deployment Node | Core Role & Capabilities |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Wazuh SIEM Manager** | v4.14.5 (Docker All-in-One) | Ubuntu `192.168.71.128` | Heart of log analysis, rule evaluation, event correlation, and Active Response dispatch. |
| **2** | **Wazuh Indexer & Dashboard**| OpenSearch 2.x (Port 443) | Ubuntu `192.168.71.128` | Centralized log indexing and storage, rendering 9 visual security monitoring panels. |
| **3** | **Suricata NIDS** | v8.x Native Linux | Ubuntu `192.168.71.128` | Network sensor monitoring `ens33`, detecting Nmap port sweeps and on-wire LFI payloads. |
| **4** | **Microsoft Sysmon** | v15.2 (Sysinternals) | Windows `192.168.71.129` | Windows Kernel monitor: Process Create (E1), LSASS Access (E10), Registry Persistence (E12/13). |
| **5** | **Wazuh Agent** | v4.14.5 (MSI Service) | Windows `192.168.71.129` | Ingests telemetry to Manager via 1514/TCP; receives emergency active response commands. |
| **6** | **n8n SOAR Engine** | Latest Docker (Port 5678) | Ubuntu `192.168.71.128` | Response orchestration brain: Threat Intel enrichment, Telegram ChatOps, WinRM execution, Jira cases. |
| **7** | **Telegram Bot & Bridge** | Telegram Cloud API + Python | Ubuntu `192.168.71.128` | 2-way interactive ChatOps interface for analysts using long-polling without inbound NAT requirements. |
| **8** | **Atlassian Jira Cloud** | REST API v3 (Project `KAN`) | Cloud SaaS | Case management platform storing investigation reports aligned with ISO 27035 audits. |
| **9** | **AbuseIPDB & VirusTotal** | REST Cloud APIs | Cloud SaaS | Threat Intelligence platforms providing IP reputation scores and malicious file hash cross-checks. |

---

# 4. DETAILED ANALYSIS OF CONFIGURATION FILES & SOURCE CODE

## 4.1. File: `manager/rules/local_rules.xml` (Core Detection Ruleset)

### Snippet 1: RDP Brute Force Password Guessing Detection (T1110)
```xml
  <!-- Rule 100001: Correlate 5 failures within 60 seconds -> Brute Force Alert -->
  <rule id="100001" level="12" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <description>Windows Brute Force Attack Detected</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
```
* **Technical Mechanism:** Inherits from parent rule `60122` (Windows Logon Failure Event 4625). The parameters `frequency="5"` and `timeframe="60"` specify that if an endpoint registers 5 authentication failures in 1 minute, the alert is escalated to **Level 12 (Critical)**.
* **Practical Benefit:** Filters out routine accidental password mistypes; only fires when automated tools like Hydra or Crowbar execute sweeps.

---

### Snippet 2: Malicious PowerShell Execution & Hierarchical Child Suppression
```xml
  <!-- Rule 100004: Catch PowerShell commands with Base64 / Hidden window flags -->
  <rule id="100004" level="12">
    <if_sid>100003</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-EncodedCommand|-enc|-w\s+hidden|-nop)</field>
    <description>CRITICAL WARNING: Malicious PowerShell Execution with Encoded/Hidden parameters detected!</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Rule 100008: Level 0 Suppression Rule dedicated to SOAR Remediation -->
  <rule id="100008" level="0">
    <if_sid>100004</if_sid>
    <field name="win.eventdata.user" type="pcre2">(?i)socrunner</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(cmd|wsmprovhost|winrshost)\.exe</field>
    <description>Suppression: Authorized SOAR Remediation PowerShell execution via WinRM</description>
  </rule>
```
* **Technical Mechanism:** Rule 100004 evaluates the `commandLine` field from Sysmon Event 1 for obfuscation flags.
* **Masterclass Architecture Tuning:** When SOAR n8n connects via WinRM to execute remediation under the `socrunner` account, remediation PowerShell commands would also trigger Rule 100004! Instead of using a loose negation clause `negate="yes"` (which attackers can bypass by spoofing usernames), we establish a **Hierarchical Child Rule 100008 with `level="0"`**:
  * Only when both criteria are met simultaneously: User is `socrunner` **AND** parent process originates from WinRM (`wsmprovhost.exe` or `winrshost.exe`) is the alert suppressed.
  * If an attacker executes commands as `socrunner` from an interactive console, the parent process is `explorer.exe` $\rightarrow$ Rule 100008 does not match $\rightarrow$ Rule 100004 fires normally!

---

### Snippet 3: LSASS Password Memory Dump Detection (T1003.001)
```xml
  <!-- Rule 100005: Sysmon Event 10 - ProcessAccess targeting lsass.exe -->
  <rule id="100005" level="12">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(MsMpEng\.exe|wmiprvse\.exe|wazuh-agent\.exe|svchost\.exe|csrss\.exe|services\.exe)</field>
    <field name="win.eventdata.grantedAccess" type="pcre2" negate="yes">^0x1000$</field>
    <description>CRITICAL WARNING: Suspicious Process Access to LSASS detected (Potential Credential Dumping)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
```
* **Technical Mechanism:** `lsass.exe` stores authentication credentials in Cleartext/NTLM Hash format within memory. Offensive tools like Mimikatz or ProcDump must request memory read privileges `PROCESS_VM_READ` (`0x0010`) or `PROCESS_ALL_ACCESS` (`0x1FFFFF`).
* **100% FP Reduction Tuning:** Routine benign system processes such as `svchost.exe` query limited process info `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION` - cannot read memory). The negation filter `negate="yes">^0x1000$` completely eliminates Windows background noise without missing actual malicious credential dumps.

---

## 4.2. File: `manager/rules/local_decoder.xml` (Apache Web Access Decoder)

```xml
<decoder name="web-access-lfi">
  <parent>windows-date-format</parent>
  <type>windows</type>
  <regex offset="after_parent">^(\S+) \S+ \S+ \[\S+ \S+\] "(\S+) (\S+) \S+" (\d+) \d+</regex>
  <order>srcip, protocol, url, id</order>
</decoder>
```
* **Technical Mechanism:** Normalizes raw Apache Common Log Format (NCSA) entries into 4 standard data fields:
  * `srcip`: Client IP address (Kali `192.168.71.130`).
  * `protocol`: HTTP request method (GET/POST).
  * `url`: Request path (e.g. `/index.php?page=../../win.ini`).
  * `id`: HTTP Status Code (200, 404, 500).
* **Significance:** Allows Rule 100002 to accurately match directory traversal strings `../` or sensitive targets such as `win.ini`.

---

## 4.3. File: `manager/soar/custom-n8n.py` (Webhook Dispatcher & Dual-Mode Resolution)

```python
def extract_ioc_data(alert_data):
    """Lab's proprietary Dual-Mode IOC Resolution mechanism"""
    rule_id = alert_data.get("rule", {}).get("id", "N/A")
    agent_info = alert_data.get("agent", {})
    endpoint_ip = agent_info.get("ip", "192.168.71.129")
    endpoint_name = agent_info.get("name", "windows-victim")

    data = alert_data.get("data", {})
    src_ip = data.get("srcip") or alert_data.get("srcip")

    # MODE 1: Remote network attack with explicit source IP (RDP, Web LFI, NIDS)
    if src_ip and src_ip not in ("-", "127.0.0.1", "0.0.0.0", ""):
        target_ioc = src_ip
        is_internal_killchain = False
    else:
        # MODE 2: Host-internal Kill Chain attack (PowerShell, UAC, LSASS)
        # Fallback to compromised endpoint's own IP for emergency network isolation
        target_ioc = endpoint_ip
        is_internal_killchain = True

    return {
        "rule_id": rule_id,
        "src_ip": target_ioc,           # Guarantees a valid real IP, never N/A
        "endpoint_ip": endpoint_ip,
        "endpoint_name": endpoint_name,
        "is_internal": is_internal_killchain
    }
```
* **Practical Value:** Eliminates runtime crashes in n8n due to null parameters, ensuring Telegram interactive buttons always execute against a valid target IP.

---

## 4.4. File: `manager/soar/telegram_bridge.py` (Long-Polling ChatOps Bridge)

```python
def poll_updates(offset=None):
    """Long-Polling Technique: Listens for Telegram events without requiring inbound NAT ports"""
    url = f"{TELEGRAM_API_BASE}/getUpdates?timeout=20"
    if offset:
        url += f"&offset={offset}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wazuh-SOAR-Telegram-Bridge"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("result", [])
    except Exception as e:
        logger.warning(f"Error fetching updates from Telegram: {e}")
    return []
```
* **Technical Mechanism:** The lab virtual machines run inside a private VMware NAT network (`192.168.71.0/24`) without a public static IP address.
* **Architectural Solution:** The script initiates an outbound connection to the Telegram Cloud API and keeps it open (20-second Long-Polling). When an analyst taps a button on mobile, Telegram immediately returns the callback query $\rightarrow$ The bridge immediately forwards it to local n8n webhooks (`http://127.0.0.1:5678/webhook/telegram-callback`) in **milliseconds** without port forwarding or ngrok tunnels.

---

## 4.5. File: `endpoint/setup_endpoint.ps1` (Master 1-Click Provisioning Endpoint)

```powershell
# Establish safe network isolation configuration (Safe Isolation)
# ALWAYS ALLOW Port 5985 (WinRM) and Port 1514 (Wazuh Agent)
New-NetFirewallRule -DisplayName "SOC-Mgmt-WinRM-In" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "SOC-Mgmt-Wazuh-Out" -Direction Outbound -RemotePort 1514 -Protocol TCP -Action Allow -Profile Any

# Deploy Canary Honey-file and attach SACL Auditing (Event 4663)
$CanaryPath = "C:\Users\Public\Documents\IT_Admin_Credentials.xlsx"
New-Item -Path $CanaryPath -ItemType File -Force
$Acl = Get-Acl $CanaryPath
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData,ExecuteFile", "Success")
$Acl.SetAuditRule($AuditRule)
Set-Acl -Path $CanaryPath -AclObject $Acl
```
* **Significance:** Guarantees defensive mechanisms can self-heal and perform remote rollback, while configuring sensitive bait files with kernel SACL auditing.

---

# 5. DETECTION RULES MATRIX (100001 - 100016)

All 16 custom rules are allocated within the safe range `100001 - 100016`, compiled automatically from Sigma YAML SSOT:

| Rule ID | Subsystem & MITRE Technique | Telemetry Ingestion Source | Logical Trigger Condition | Severity (Level) | False Positive Suppression Method (Tuning) |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **100001** | `T1110` (RDP Brute Force) | Windows Security Event 4625 | 5 failed authentications within 60s from same IP | **Level 12** | `frequency="5"` threshold eliminates mistyped passwords. |
| **100002** | `T1190` (Web LFI / Traversal) | Apache `access.log` via custom decoder | URL contains `../`, `..%2f`, `win.ini`, `boot.ini` | **Level 10** | Filters distinct Directory Traversal patterns. |
| **100003** | `Base Filter` (Process Creation) | Sysmon Event 1 | Base filter aggregating all process creation events | **Level 0** | Does not fire alerts; acts as parent for child rules. |
| **100004** | `T1059.001` (PowerShell Obfuscation) | Sysmon Event 1 | CommandLine contains `-enc`, `-EncodedCommand`, `-w hidden` | **Level 12** | Evaluates parent process and Base64 payload. |
| **100005** | `T1003.001` (LSASS Credential Dump) | Sysmon Event 10 | `TargetImage` is `lsass.exe` with RAM read permissions | **Level 12** | **Negates `0x1000` permission**, eliminating 100% FP from `svchost.exe`. |
| **100006** | `T1547.001` (Registry Run Persistence) | Sysmon Event 12/13 | Writes key to `CurrentVersion\Run` or `RunOnce` | **Level 10** | Monitors untrusted processes configuring startup persistence. |
| **100007** | `T1548.002` (UAC Bypass Fodhelper) | Sysmon Event 12/13 | Hijacks registry key `ms-settings\Shell\Open\command` | **Level 12** | Fodhelper never spawns child binaries $\rightarrow$ 100% precision. |
| **100008** | `Child Suppression` (SOAR Remediation) | Sysmon Event 1 | User `socrunner` executes PowerShell via WinRM | **Level 0** | Suppresses alerts during authorized SOAR remediation actions. |
| **100009** | `Child Suppression` (UAC Cleanup) | Sysmon Event 12/13 | User `socrunner` cleans up UAC registry keys | **Level 0** | Enables SOAR registry cleanup without self-alert loops. |
| **100010** | `Child Suppression` (Run Key Cleanup) | Sysmon Event 12/13 | User `socrunner` cleans up Run Persistence keys | **Level 0** | Enables SOAR Run key cleanup without re-triggering alerts. |
| **100011** | `T1046` (Nmap Reconnaissance) | Suricata NIDS (`eve.json`) | Matches Nmap Stealth SYN port scan signature | **Level 10** | Inspects raw packets on the wire before hitting the host. |
| **100012** | `T1190` (LFI Attack on Wire) | Suricata NIDS (`eve.json`) | Signature matches traversal characters in URI | **Level 12** | Validates network tier independently of web server logs. |
| **100013** | `T1595.002` (Vulnerability Scanner) | Suricata NIDS (`eve.json`) | Identifies signatures of Nikto, sqlmap, Gobuster | **Level 10** | Blocks automated scanners during early Reconnaissance. |
| **100014** | `T1083` (Canary Honey-File Accessed) | Windows Security Event 4663 | SACL Audit fires when `IT_Admin_Credentials.xlsx` is accessed | **Level 12** | **Zero False Positive (0% FP)**; auto-triggers DFIR RAM dump. |
| **100015** | `T1078` (Honey-Account Logon Tripwire)| Windows Security Event 4625 | Login attempt against decoy account `backup_admin` | **Level 12** | **Zero False Positive (0% FP)**; flags credential spray against decoy. |
| **100016** | `T1046` (Decoy Port 21 Probe) | Windows EventLog / Port Decoy | Connection attempt to decoy FTP Port 21 | **Level 10** | Intercepts internal network reconnaissance sweeps. |

---

# 6. CLOSED-LOOP INCIDENT RESPONSE (SOAR CLOSED-LOOP & 1-CLICK ROLLBACK)

The incident response lifecycle adheres to **NIST SP 800-61 Rev. 2** across 5 phases:

```text
===================================================================================================
                         SOAR CLOSED-LOOP INCIDENT RESPONSE LIFECYCLE
===================================================================================================

[ STEP 1: DETECTION & TRIAGE ]
  • Wazuh fires an alert (e.g. Rule 100007 - UAC Bypass or Rule 100014 - Canary File).
  • wazuh-integratord routes alert JSON to custom-n8n.py -> Automatically resolves target IP.

[ STEP 2: CONTEXT ENRICHMENT ]
  • n8n Webhook Ingest receives payload:
    - If Public IP: Queries AbuseIPDB API for Abuse Confidence Score & ISP country.
    - If suspicious file: Cross-checks VirusTotal API (Rule 87105).
  • n8n formats a rich HTML Alert Card.

[ STEP 3: CHATOPS & 2-WAY APPROVAL (Human-in-the-Loop) ]
  • Dispatches Telegram message to @my_wazuh_soc_alert_bot with 3 interactive action buttons:
    - [🚫 Block IP 24h]            -> Emergency host isolation or attacker IP drop.
    - [🔄 Unblock (Rollback)]      -> Instant rollback if false containment is detected.
    - [📋 Open Jira Ticket]        -> Initiates L2 investigation record on Jira Cloud.

[ STEP 4: SAFE CONTAINMENT & FORENSICS ]
  • Analyst taps [🚫 Block IP 24h]:
    - n8n executes WinRM PowerShell against Windows 10:
      New-NetFirewallRule -DisplayName "SOAR-BLOCK" -Direction Inbound/Outbound -Action Block
    - Guarantees management channels Port 5985 (WinRM) and Port 1514 (Wazuh Agent) remain open.
  • If a Deception event occurs: Automatically invokes collect_evidence.ps1 to acquire MiniDump RAM,
    netstat, EVTX logs, packages into a .zip archive, and attaches it directly to the Jira Ticket.

[ STEP 5: SELF-HEALING ROLLBACK (1-Click Rollback in < 5s) ]
  • If the SOC operator detects false containment or remediation is complete:
    - Analyst taps [🔄 Unblock (Rollback)] on Telegram.
    - n8n runs WinRM: Remove-NetFirewallRule -DisplayName "SOAR-BLOCK*"
    - Endpoint connectivity is restored to baseline within 3-5 seconds without manual intervention.
```

---

# 7. 8 CAPSTONE DEFENSE & TECHNICAL INTERVIEW Q&A (VIVA DEFENSE Q&A)

### Question 1: Why must the endpoint integrate both Sysmon and Wazuh Agent?
* **Answer:** By default, Wazuh Agent primarily aggregates basic Windows Event Logs and superficial operating system states. Sophisticated techniques in the **MITRE ATT&CK Kill Chain** such as **LSASS Memory Dumping (T1003.001)** or **UAC Bypass via Fodhelper (T1548.002)** do not leave definitive traces in standard Windows Event Logs. Microsoft Sysmon v15.2 operates as a kernel-level filter driver (`SysmonDrv.sys`), providing granular telemetry: Event 1 (Full CommandLine with SHA256 hashes), Event 10 (Inter-process memory handle access rights), and Event 12/13 (Granular registry modifications). Combining Sysmon with Wazuh transforms the endpoint into a true **EDR sensor**.

### Question 2: How does the Rule 100005 (LSASS) tuning technique eliminate 100% of false positives?
* **Answer:** When monitoring `lsass.exe` using Sysmon Event 10, real-world environments suffer from alert fatigue because benign system processes like `svchost.exe` (hosting Local Session Manager) or `MicrosoftEdgeUpdate.exe` periodically query LSASS. I analyzed the `GrantedAccess` bitmask: Routine system processes request limited information access `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION` - cannot read memory contents). In contrast, offensive dump tools such as Mimikatz or ProcDump must request read privileges `0x0010` (`PROCESS_VM_READ`) or `0x1FFFFF` (`PROCESS_ALL_ACCESS`). By appending the negation filter `<field name="win.eventdata.grantedAccess" type="pcre2" negate="yes">^0x1000$</field>`, the system suppresses 100% of Windows background noise while ensuring actual credential theft attempts are caught.

### Question 3: Why use a Hierarchical Suppression Rule (Level 0) instead of adding `negate="yes"` to the parent rule?
* **Answer:** If we write `negate="yes"` directly checking the user `socrunner` inside Rule 100004, Wazuh XML evaluation applies a **loose OR logic** across multiple negation conditions. An attacker could bypass detection simply by matching a single whitelisted attribute. Therefore, I implemented the **Hierarchical Child Suppression Rule (`level="0"`)** architecture:
  * Child Rule 100008 inherits from Parent Rule 100004.
  * In the child rule, multiple `<field>` tags enforce **strict AND logic**: The execution must simultaneously match user `socrunner` **AND** have its parent process originate from WinRM (`wsmprovhost.exe` or `winrshost.exe`).
  * Consequently, only authorized SOAR remediation actions are suppressed, completely preventing attackers from leveraging whitelists for evasion.

### Question 4: What critical challenge does the Dual-Mode IOC Resolution mechanism resolve in SOAR?
* **Answer:** Standard SOAR workflows assume every incident originates externally with a distinct `srcip`. However, during a **local Kill Chain execution** (such as encoded PowerShell, UAC Bypass, or LSASS dump), the attacker is already inside the endpoint, leaving `srcip` null or empty. Passing this directly into SOAR leads to `Target: N/A` errors, failing firewall rule generation. My `custom-n8n.py` script applies dual-mode resolution: When an external IP is absent, it automatically falls back to using the compromised endpoint's own IP address (`192.168.71.129`) as the containment target, immediately isolating the victim host from the network and severing lateral movement.

### Question 5: How do Safe Host Isolation and 1-Click Rollback operate?
* **Answer:** When an endpoint is isolated via host firewall policies, applying an unconditional block policy (Block All Inbound & Outbound) breaks all connectivity to the SIEM/SOAR management plane. The SOC analyst would lose remote control and be forced to physically access the machine. In this project, I enforced **Safe Isolation**:
  * The firewall policy **always allows Port 5985 (WinRM)** and **Port 1514/1515 (Wazuh Agent)**.
  * Because the control channel remains active, the analyst can tap **[🔄 Unblock (Rollback)]** on Telegram, which triggers a WinRM call to remove the block rule, restoring full network connectivity in **under 5 seconds**.

### Question 6: How does Deception Technology in this project differ from traditional SIEM detection?
* **Answer:** Traditional SIEM detection relies on behavioral anomaly heuristics, which inherently produce a baseline rate of False Positives. In contrast, **Deception Technology** deploys decoy assets with zero legitimate business utility (Canary Honey-file `IT_Admin_Credentials.xlsx`, honey-account `backup_admin`, Decoy Port 21). Legitimate employees never touch these assets. Therefore, any interaction carries **100% confidence of malicious activity (0% False Positive)**. Upon receiving a SACL Event 4663 trigger, the system immediately runs automated DFIR scripts (Live Forensics: MiniDump RAM, netstat network states, EVTX logs), compresses them into a `.zip` archive, and uploads them directly to Jira Cloud for Tier-2 investigators.

### Question 7: What are the architectural advantages of Detection-as-Code (DaC) and the SigWaz Compiler?
* **Answer:** Manually editing XML files directly on production SIEM servers risks syntax errors that can crash the `wazuh-analysisd` service and lacks audit versioning. I adopted **Detection-as-Code**:
  * Detection rules are authored in **Sigma YAML** within `manager/rules/sigma/` (serving as the Single Source of Truth - SSOT).
  * The `scripts/sigma_compiler.py` compiler translates Sigma YAML into production Wazuh XML and automatically generates hierarchical Level 0 suppression rules for SOAR.
  * Integrated into **GitHub Actions CI/CD** (`.github/workflows/test.yml`): The pipeline executes 22 automated pytest checks validating XML syntax, Rule ID uniqueness, MITRE ATT&CK schema compliance, and zero-drift verification (`--check`) before allowing pull requests to merge into production.

### Question 8: Why choose n8n as the SOAR engine instead of TheHive or Cortex?
* **Answer:** TheHive is primarily a **Case Management** platform, while Cortex is an observable analyzer; neither possesses a native, flexible workflow orchestration engine. n8n supports native JavaScript/Node.js scripting, enabling flexible payload manipulation (such as Base64 formatting for Jira REST API v3, dynamic switch routing), real-time 2-way Telegram ChatOps integration, and direct API interoperability with Jira Cloud within a single visual workflow canvas, with minimal resource overhead running in a lightweight Docker container.
