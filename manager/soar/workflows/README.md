# 🤖 n8n SOAR Workflows

This directory stores 3 standardized workflows for the **n8n SOAR Engine** in JSON format, ready for direct import into the n8n Web UI (`http://192.168.71.128:5678`).

---

## 📌 Workflow Catalog

| Configuration File | Workflow Name | Functional Description |
| :--- | :--- | :--- |
| `01_wazuh_soar_threat_enrichment.json` | **Workflow 1: Threat Enrichment & ChatOps Dispatcher** | Ingests Webhook alerts from Wazuh (`/webhook/wazuh-alert`), parses IoCs, queries AbuseIPDB/VirusTotal, generates HTML Cards with inline buttons, and dispatches to Telegram Bot. |
| `02_containment_action_executor.json` | **Workflow 2: Containment & Case Management Executor** | Listens for callback events when an Analyst clicks interactive buttons: executes process termination (`Stop-Process`), host isolation via WinRM, network unblock rollback (Rollback), and Incident Ticket creation on Jira Cloud REST API v3. |
| `03_scheduled_healthcheck_cron.json` | **Workflow 3: Scheduled Healthcheck Cron** | Runs automatically on a 6-hour recurring schedule to check availability of virtual machines, Wazuh Manager services, and Docker containers, transmitting status reports to Telegram. |

---

## ⚡ Import Instructions for n8n
1. Access n8n Web UI: `http://192.168.71.128:5678`
2. Select **Workflows** $\rightarrow$ **Add Workflow** $\rightarrow$ click the three dots icon $\rightarrow$ select **Import from File**.
3. Select each `.json` file sequentially and click **Activate**.
