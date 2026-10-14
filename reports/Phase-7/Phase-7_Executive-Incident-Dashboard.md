# EXECUTIVE INCIDENT DASHBOARD DEPLOYMENT REPORT ON WAZUH SIEM (PHASE 7)

* **Project:** Centralized Cybersecurity Monitoring & Incident Response System (Wazuh SIEM/XDR Lab)
* **Simulated Role:** SOC Lead / Detection Engineer / SIEM Architect
* **Execution Environment:**
  * **SIEM Infrastructure:** Wazuh Dashboard 4.14.5 / OpenSearch Dashboards 2.x (Port 443 - IP: `192.168.71.128`).
  * **Telemetry Data Sources:** Index pattern `wazuh-alerts-*` storing Windows 10 workstation telemetry (`192.168.71.129`), Sysmon v15.2, and Kali Linux attacker host (`192.168.71.130`).
  * **Deployment Configuration File:** [`deployment/dashboards/soc_lab_executive_dashboard.ndjson`](../../deployment/dashboards/soc_lab_executive_dashboard.ndjson).
  * **Automated Import Tool:** [`scripts/import_dashboard.py`](../../scripts/import_dashboard.py).

---
![Overview of the Executive Incident Dashboard on Wazuh](images/wazuh_dashboard_overview.png)

## I. OBJECTIVES & OPERATIONAL VALUE OF THE EXECUTIVE DASHBOARD

In a modern Security Operations Center (Next-Gen SOC), reading raw terminal log streams or Telegram notifications alone is insufficient for management (SOC Manager/CISO) and audit committees. The system requires a **Centralized Monitoring Interface (Single Pane of Glass)** capable of:
1. **Holistically Visualizing the Security Posture:** Transforming raw JSON logs into intuitive, easy-to-understand visual charts.
2. **Tailored to Practical Lab Threat Scenarios:** Deeply focused on 6 critical attack techniques (RDP Brute Force, Web LFI, and 4 Windows Kill Chain stages) rather than displaying generic telemetry.
3. **Tracking Operational Real-Time KPIs:** Benchmarking detection response time (MTTA < 3s) and automated containment time (MTTR < 20s).
4. **Standardized Code Packaging (Saved Objects .ndjson):** Enabling 1-click automated import into any Wazuh cluster without requiring manual chart-by-chart configuration.

---

## II. 7-COMPONENT VISUALIZATION MATRIX

Official dashboard title: **`SOC Lab - Executive Incident Overview`**, consisting of 7 specialized widgets:

| No. | Widget Name | Chart Type | Monitoring Significance & Technical Metrics |
| :---: | :--- | :---: | :--- |
| **1** | `Total Security Incidents KPI` | **Metric** | Counter tracking total security incidents in the lab, categorizing severity levels and response KPIs. |
| **2** | `Incident Severity Distribution` | **Donut Chart** | Percentage distribution of alert severities: Red (Level 12 - Critical), Orange (Level 10 - High), Blue (Level 3 - Info). |
| **3** | `MITRE ATT&CK Techniques Heatmap` | **Horizontal Bar** | Violation metrics across 6 lab attack techniques: `T1110.001`, `T1190`, `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001`. |
| **4** | `Top Attacker Source IPs` | **Horizontal Bar** | Ranking of top attacker IP addresses (led by Kali Linux attacker machine `192.168.71.130`). |
| **5** | `Target Endpoints & Users` | **Data Table** | Telemetry breakdown of victim Windows 10 endpoints (`agent.name`) and compromised user accounts (`testw`, `socrunner`). |
| **6** | `Malicious Processes Telemetry` | **Data Table** | Breakdown of malicious binaries and processes (`powershell.exe`, `fodhelper.exe`, `lsass.exe`, `httpd.exe`). |
| **7** | `Real-Time Security Incident Stream` | **Saved Search** | Live incident stream grid: `timestamp`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre.id`, `data.srcip`, `agent.name`. |
