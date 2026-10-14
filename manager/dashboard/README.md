# 📊 Wazuh SOC Lab - Executive Incident Overview Dashboard

> **Subsystem:** Pillar 3 - Specialized Custom Dashboard on Wazuh SIEM  
> **Compatibility:** Wazuh Dashboard 4.14.5 / OpenSearch Dashboards 2.x (Port 443)  
> **Configuration File:** [`soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson)

---

## 📌 Overview

By default after installation, Wazuh Dashboard only provides generic monitoring views (*Security Events, Integrity Monitoring, generic MITRE ATT&CK*). 

The configuration file [`soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson) is a **tailored Custom Dashboard** designed specifically for the project's lab scenarios:
* **Dashboard Title:** `SOC Lab - Executive Incident Overview`
* **Objective:** Visualize the entire real-world attack chain (RDP Brute Force, Web LFI, and the 4-stage Windows MITRE Kill Chain), highlighting the Kali Linux attacking host (`192.168.71.130`), the Windows 10 target endpoint (`192.168.71.129`), and operational SOC KPIs (MTTA < 3s, MTTR < 20s).

---

## 🎨 Layout & 7 Visualizations

| Component | Widget Type | Data Target & Operational Meaning |
| :--- | :---: | :--- |
| **1. Total Security Incidents KPI** | `Metric` | Counter metric tracking total security incidents detected in the Lab. |
| **2. Incident Severity Distribution** | `Donut Chart` | Severity distribution percentage: Red (Level 12 - Critical), Orange (Level 10 - High), Blue (Level 3 - Info). |
| **3. MITRE ATT&CK Techniques Heatmap** | `Horizontal Bar` | Analysis of attack volumes across 6 real-world techniques: `T1110.001`, `T1190`, `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001` alongside corresponding Tactics. |
| **4. Top Attacker Source IPs** | `Horizontal Bar` | Leaderboard of top attacking source IPs (led by Kali Linux `192.168.71.130`). |
| **5. Target Endpoints & Compromised Users** | `Data Table` | Statistics on victim Windows 10 endpoints (`agent.name`) and targeted user accounts (`testw`, `socrunner`). |
| **6. Malicious Processes Telemetry** | `Data Table` | Statistics on suspicious executables and processes (`powershell.exe`, `fodhelper.exe`, `lsass.exe`, `httpd.exe`). |
| **7. Real-Time Security Incident Stream** | `Saved Search` | Real-time incident stream log table: `timestamp`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre.id`, `data.srcip`, `agent.name`. |

---

## 🚀 Dashboard Import Instructions (2 Methods)

### 🔹 Method 1: 1-Click Automated Import via Python CLI (Recommended)

Run the built-in automation script from the repository root:

```powershell
python scripts/import_dashboard.py
```

* The script automatically reads parameters from `.env` (or Docker configuration), connects over HTTPS port 443 to Wazuh Dashboard, and imports all 9 Saved Objects in just **1.5 seconds**.
* Upon completion, the script displays a confirmation message along with a direct access URL.

---

### 🔹 Method 2: Manual Import via OpenSearch Dashboards Web UI (GUI)

To import manually through a web browser:

1. Log in to Wazuh Dashboard: **`https://192.168.71.128`** (Port 443).
2. Click the hamburger Menu icon (`≡`) in the top left corner.
3. Scroll down to **OpenSearch Dashboards** -> Select **Stack Management**.
4. In the left sidebar, click **Saved Objects**.
5. Click the **Import** button in the top right corner.
6. Drag and drop or select the file [`deployment/dashboards/soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson).
7. Toggle **Automatically overwrite all saved objects** -> Click **Import**.
8. Click **Done** to complete.

---

## 🔗 Accessing the Dashboard

After successful import, access the Dashboard via:
* **Direct link:** `https://192.168.71.128/app/dashboards#/view/soc-lab-executive-overview`
* **Or via Menu:** Click Menu `≡` -> Select **Dashboard** -> Click **`SOC Lab - Executive Incident Overview`**.
