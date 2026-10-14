# 📘 SOC INCIDENT RESPONSE PLAYBOOKS

This document standardizes the procedures for reception, investigation, containment, recovery, and digital evidence preservation (Standard Operating Procedures - SOP) for **SOC Analyst (L1/L2)**, **Incident Responder**, and **DFIR Specialist** teams, adhering to international standards **NIST SP 800-61 Rev. 2** and the **SANS PICERL** framework.

---

## 🧭 Incident Response Framework (NIST / SANS Framework)

```
       ┌────────────────────────┐
       │   1. PREPARATION       │ (Preparation: Configure Sysmon, Rules, Suricata, Deception Grid)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   2. IDENTIFICATION    │ (Detection & Triage: Triage, Severity, Zero False Positive)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   3. CONTAINMENT       │ (Containment: 1-Click Safe Host Isolation, Active Response, WinRM Drop)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   4. ERADICATION       │ (Eradication: Kill processes, Clean Registry Run keys, Disable accounts)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   5. RECOVERY          │ (Recovery: 1-Click Rollback 5s, Password reset, Enhanced monitoring)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   6. LESSONS LEARNED   │ (Post-Incident: Lessons learned meeting, Optimize Sigma Rules, Jira RCA)
       └────────────────────────┘
```

---

## 📊 Severity Classification Matrix (Severity Matrix)

| Level | Definition | Trigger Criteria | Response SLA |
| :--- | :--- | :--- | :---: |
| **P1 - Critical** | Critical incident threatening the entire system; administrative credential disclosure or Deception canary tripped. | • Interaction with Deception Honey-File / Honey-Account decoy (0% FP).<br/>• Successful memory dump of `lsass.exe`.<br/>• Successful login following a Brute Force sequence (Event 4624 Type 10). | **< 15 minutes**<br/>*(Instant automated)* |
| **P2 - High** | Targeted attack in progress; malware execution or workstation UAC elevation. | • Execution of Base64 encoded PowerShell (`T1059.001`).<br/>• Registry hijack for UAC Bypass `ms-settings` (`T1548.002`).<br/>• Web LFI successfully reading system configuration files over the network. | **< 30 minutes** |
| **P3 - Medium** | Network reconnaissance activity or high-volume automated attacks blocked by Active Response. | • Nmap Stealth SYN port scan detected by Suricata NIDS (`T1046`).<br/>• Automated vulnerability scanners (Nikto, Gobuster) probing Web ports.<br/>• RDP Brute Force successfully blocked by Firewall. | **< 2 hours** |
| **P4 - Low** | Isolated anomalous activity, high probability of legitimate user mistyping credentials. | • 1–3 failed login attempts from an internal user workstation.<br/>• Common HTTP 404 syntax error requests. | **< 8 hours** |

---

## 🗂️ Comprehensive Catalog of 6 Operational Playbooks (SOP-01 to SOP-06)

| SOP Code | Standard Operating Procedure | MITRE Technique | Applied Subsystem |
| :---: | :--- | :---: | :--- |
| [**SOP-01**](SOP-01_RDP_Brute_Force_Response.md) | **RDP Password Brute-Force Attack Response** | **T1110.001** | Windows Security Event ID 4625 & Netsh Firewall Drop |
| [**SOP-02**](SOP-02_Web_LFI_Mitigation.md) | **Web Application LFI & Path Traversal Exploitation Response** | **T1190** | Apache Access Logs, Sysmon Event ID 1 & 11 |
| [**SOP-03**](SOP-03_SOAR_Automated_Containment.md) | **SOAR Automated Response & Closed-Loop Containment (Rollback 5s)** | **T1110, T1190, T1059** | n8n SOAR, Telegram ChatOps 2-Way, Jira Cloud REST v3 |
| [**SOP-04**](SOP-04_Endpoint_Kill_Chain_Response.md) | **Malware Kill Chain & LSASS Credential Dumping Response** | **T1059, T1548, T1547, T1003** | Sysmon Event ID 1, 10, 12, 13 & Active Response `kill-process` |
| [**SOP-05**](SOP-05_Network_NIDS_Suricata_Response.md) | **Suricata NIDS Network Intrusion & XDR Correlation Response** | **T1046, T1595, T1190** | Suricata 8.0.7 EVE JSON Stream (`ens33`) & Packet Analysis |
| [**SOP-06**](SOP-06_Deception_Honeypot_and_Forensics.md) | **Deception Canary Decoy Response (0% FP) & DFIR Digital Forensics** | **T1083, T1078, T1046** | Windows SACL 4663, Honey-Account, FTP Decoy & RAM MiniDump |
