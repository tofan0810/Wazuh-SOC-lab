# 🧭 Command Central Hub

The `commands/` directory contains all guides and cheatsheets for remote command execution, attack triggering, automated testing, and operations for the Wazuh SOC Lab environment.

---

## 📚 Guide Directory

| Guide | Purpose & Key Content | Quick Link |
| :--- | :--- | :--- |
| **1. Remote Execution Guide** | Guide for invoking SSH/WinRM commands from the Host machine PowerShell into the 3 virtual machines (Kali, Wazuh, Windows) without switching VMware console windows. | [`REMOTE_EXECUTION.md`](REMOTE_EXECUTION.md) |
| **2. Attack Triggering & E2E Testing Guide** | Guide for running 3 attack scenarios (RDP, LFI, Full Kill Chain), automated Python runner test suites, and Wazuh rule validation. | [`ATTACK_AND_TEST_GUIDE.md`](ATTACK_AND_TEST_GUIDE.md) |
| **3. SOAR & ChatOps Operations Guide** | Guide for managing n8n Docker, the Telegram Bridge daemon, firewall unblock rules, and Jira Cloud integration verification. | [`SOAR_CHATOPS_OPS.md`](SOAR_CHATOPS_OPS.md) |
| **4. Configuration Sync Guide (.env)** | Guide for using the automated `sync_env.bat` / `sync_env.py` tools to propagate API keys, tokens, and configuration changes across the entire system. | [`CONFIG_SYNC_COMMANDS.md`](CONFIG_SYNC_COMMANDS.md) |

---

## 📌 Lab Infrastructure & Services Quick Reference

| Virtual Machine / Service | IP / Port | Protocol / Account | Purpose |
| :--- | :--- | :--- | :--- |
| **Kali Linux** | `192.168.71.130` (Port 22) | SSH (User: `kali`) | Simulated Attacker Machine |
| **Ubuntu Wazuh** | `192.168.71.128` (Port 22) | SSH (User: `nguyentoan`) | SIEM Server & SOAR Engine |
| **Windows 10** | `192.168.71.129` (Port 5985) | WinRM (User: `socrunner`) | Victim Endpoint Workstation |
| **Wazuh Dashboard** | `https://192.168.71.128:443` | Web UI (`admin`) | SIEM Monitoring, Alerts, Dashboards |
| **n8n SOAR Editor** | `http://192.168.71.128:5678` | Web UI | SOAR Workflow Design & Monitoring |
| **Telegram Bot** | `@my_wazuh_soc_alert_bot` | HTTPS (Chat ID: `8696241190`) | ChatOps Notification & Approval Channel |
| **Jira Cloud** | `https://tn421015.atlassian.net` | REST API v3 (Project: `KAN`) | Incident Case Management System |

---

## ⚡ Frequently Used Commands (Quick Cheatsheet)

```powershell
# 1. Check health across the entire lab:
python tests/e2e/lab_health.py

# 2. Synchronize configuration after editing .env (1-Click):
.\sync_env.bat

# 3. Trigger attack & test Scenario 3 (Full Kill Chain):
python tests/e2e/scenario_full_killchain.py --execute

# 4. Monitor real-time alerts on Wazuh Manager:
ssh wazuh-vm "sudo tail -f /var/ossec/logs/alerts/alerts.json"

# 5. View incoming Telegram ChatOps button callback logs:
ssh wazuh-vm "tail -f /home/nguyentoan/n8n-docker/telegram_bridge.log"
```
