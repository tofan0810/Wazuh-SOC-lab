# 💻 Wazuh Endpoint Provisioning Package (Windows 10)

Comprehensive packaging of configurations, security modules, and setup scripts for the **Windows 10 Target endpoint (`192.168.71.129`)**.

---

## ⚡ 2-STEP QUICKSTART DEPLOYMENT

### Step 1: Install Base Software (User Pre-requisite)
If configuring a fresh Windows 10 machine without software installed, download and install the following two official tools:

1. **Install Wazuh Agent 4.14.5 (Official):**
   * Download the MSI installer: [wazuh-agent-4.14.5-1.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi)
   * Open CMD (Run as Admin) and execute the installation command:
     ```cmd
     msiexec.exe /i wazuh-agent-4.14.5-1.msi /q WAZUH_MANAGER="192.168.71.128" WAZUH_REGISTRATION_SERVER="192.168.71.128"
     ```

2. **Install Microsoft Sysmon v15.2 (Sysinternals):**
   * Download the zip package: [Microsoft Sysinternals Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip)
   * Extract the zip file to a directory (e.g., `C:\Sysmon` or ensure `Sysmon64.exe` is available in PATH).
   * Run initial installation:
     ```cmd
     Sysmon64.exe -accepteula -i
     ```

---

### Step 2: Run Lab Master Script (1-Click Master Setup)
Open a **PowerShell window with Administrator privileges** in this directory and execute:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_endpoint.ps1 -WazuhManagerIP "192.168.71.128"
```

**The `setup_endpoint.ps1` script automatically handles 100% of the remaining configuration:**
1. ✅ Ingests the Sysmon event filtering configuration aligned with MITRE ATT&CK (`config\sysmon-config.xml`).
2. ✅ Ingests the Agent `ossec.conf` configuration (enabling real-time FIM for `C:\Users\Public`, Sysmon Eventchannel monitoring, and Apache logs).
3. ✅ Registers Active Response scripts (`kill-process.ps1`, `collect-evidence.ps1`) into `C:\Program Files (x86)\ossec-agent\active-response\bin\`.
4. ✅ Activates Windows Object Access Auditing (SACL Event 4663).
5. ✅ Initializes the Deception honey-token ecosystem (Canary File `IT_Admin_Credentials.xlsx` and Honey-Account `backup_admin`).
6. ✅ Configures the secure WinRM management channel (Port 5985) for SOAR closed-loop response.
7. ✅ Restarts the Wazuh Agent service.

---

## 🗂️ Directory Structure `endpoint/`

```text
endpoint/
├── README.md                      # Windows 10 endpoint deployment guide
├── setup_endpoint.ps1             # 1-Click master script automating full endpoint configuration
├── config/
│   ├── ossec.conf                 # Wazuh Agent baseline configuration (FIM, Channels, AR)
│   └── sysmon-config.xml          # Sysmon v15.2 configuration optimized for MITRE ATT&CK
├── active-response/               # Instant endpoint response scripts
│   ├── kill-process.cmd / .ps1    # Malicious process termination (Safe Whitelist preventing BSOD)
│   └── collect-evidence.cmd / .ps1# Automated evidence bundle: RAM dump + netstat + EVTX into .zip
└── deception/                     # Proactive deception decoy framework (0% False Positive)
    ├── setup_canary.ps1           # Canary file SACL generation & decoy account backup_admin
    ├── network_decoy.py           # Simulated FTP Port 21 decoy service listener
    └── collect_evidence.ps1       # Live digital forensics evidence extraction script
```
