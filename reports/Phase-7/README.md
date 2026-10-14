# 📊 Phase 7: Executive Incident Dashboard

Directory containing technical reports and proof-of-concept evidence for **Phase 7**, designing and deploying a professional incident visualization interface on **OpenSearch Dashboards** (Wazuh Dashboard Port 443).

---

## 📌 Main Technical Report
* **Detailed Document:** [`Phase-7_Executive-Incident-Dashboard.md`](Phase-7_Executive-Incident-Dashboard.md)
* **Contents:**
  - Design of the **`SOC Lab - Executive Incident Overview`** Dashboard comprising 7 specialized visualizations (MTTA/MTTR KPIs, Severity Distribution Donut chart, MITRE ATT&CK Heatmap, Attacker IP Leaderboard, Endpoint & User table, Malicious Processes telemetry, and Real-time Incident Stream).
  - Automated publishing and rapid 1-click import of all 9 Saved Objects via REST API in just 1.5 seconds using the [`scripts/import_dashboard.py`](../../scripts/import_dashboard.py) script.
