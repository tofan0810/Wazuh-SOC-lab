# 🍯 Deception Technology & Digital Forensics (Phase 10)

This directory contains deployment scripts for proactive deception technology (**Active Defense / Deception Grid**) and automated digital forensic evidence collection modules (**Live Forensics Preservation**).

---

## 📌 Component Directory

| File | Decoy Type / Function | Trigger Mechanism | Wazuh Rule & Response |
| :--- | :--- | :--- | :--- |
| `setup_canary.ps1` | **Canary Honey-File & Honey-Account** | Creates `C:\Users\Public\IT_Admin_Credentials.xlsx` with SACL Audit for Read operations; creates decoy user account `backup_admin`. | **Rule 100014** (Canary File read - Event 4663)<br/>**Rule 100015** (Honey-Account logon - Event 4625)<br/>*0% False Positive rate (Zero FP)*. |
| `network_decoy.py`<br/>`network_decoy.ps1` | **Network Service Decoy (FTP 21)** | Socket listener binding TCP port 21, returning banner `220 Microsoft FTP Service`, logging service reconnaissance (T1046). | **Rule 100016** (FTP Decoy Touch)<br/>Instantly blocks attacker IP. |
| `collect_evidence.ps1` | **Automated DFIR Triage** | Automatically captures process RAM mini-dump, network connection tables, active sessions, and security EVTX logs compressed into `Evidence_<AlertId>.zip`. | Automatically attached to the **Jira Cloud Incident Ticket**. |

---

## ⚡ Deployment Commands on Windows Endpoint
```powershell
# 1. Activate Canary File & Honey-Account traps
powershell -ExecutionPolicy Bypass -File deployment\deception\setup_canary.ps1

# 2. Start Network Decoy (FTP Port 21)
python deployment\deception\network_decoy.py
```
