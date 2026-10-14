# 🔌 Integrations & SOAR Extensions

This directory stores third-party integration modules, extending the capabilities of **Wazuh SIEM** into **Threat Intelligence** and **SOAR Automated Incident Orchestration**.

---

## 🗂️ Subsystem Architecture

| Subsystem | Path | Primary Function |
| :--- | :--- | :--- |
| **n8n SOAR & Jira Cloud** | [`manager/soar/`](../manager/soar/) | Central SOAR orchestration engine: Receives webhook alerts from Wazuh, enriches IoCs via AbuseIPDB/VirusTotal, dispatches bidirectional interactive 2-way ChatOps alert cards, and manages incident lifecycles via Jira Cloud REST API v3. |
| **Telegram ChatOps** | [`telegram/`](telegram/) | Real-time alerting bridge to Telegram Bot (`@my_wazuh_soc_alert_bot`), formatting HTML alert cards and supporting incident response interactions. |
| **VirusTotal Threat Intel** | [`virustotal/`](virustotal/) | Configuration for the `wazuh-integratord` module to cross-reference file hashes (SHA256) from FIM Syscheck against >70 Antivirus Cloud Engines, triggering Rule 87105 upon malware detection. |
