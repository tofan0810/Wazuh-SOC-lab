# 🛑 Endpoint Active Response Scripts

This directory contains real-time response scripts triggered by the **Wazuh Active Response Engine** on the Windows 10 Endpoint workstation.

---

## 📌 Script Directory

| Script | Response Objective | Safety Guard Mechanism |
| :--- | :--- | :--- |
| `kill-process.ps1`<br/>`kill-process.cmd` | Instantly terminates malicious processes (`Stop-Process -Force`) upon detecting Encoded PowerShell (Rule 100004) or LSASS Memory Dump (Rule 100005). | **Safe Whitelist:** Strictly prevents killing vital operating system processes (`csrss.exe`, `lsass.exe`, `winlogon.exe`, `services.exe`, `wazuh-agent.exe`) to prevent Blue Screen of Death (BSOD). |
| `collect-evidence.ps1`<br/>`collect-evidence.cmd` | Performs digital forensic triage: RAM mini-dump, network connections via `netstat -ano`, active sessions, and EVTX logs prior to threat mitigation. | Automatically enforces timeouts, compresses artifacts into `.zip` archives, and prevents endpoint performance degradation. |

---

## 🛠️ Deployment Path on Windows Endpoint
All `.cmd` and `.ps1` files are deployed to the Wazuh Agent Active Response directory:
```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```
Configured within `<active-response>` blocks in the `ossec.conf` file.
