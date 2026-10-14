# ⚡ Phase 5: SOAR Orchestration & Closed-Loop Response

Directory containing technical reports and documentation for **Phase 5**, implementing automated incident response and orchestration via SOAR with n8n, Telegram ChatOps, and Atlassian Jira Cloud.

---

## 📌 Technical Reports Directory

| Report | Core Focus |
| :--- | :--- |
| [`Phase-5_SOAR-Workflow-Automation.md`](Phase-5_SOAR-Workflow-Automation.md) | **Part 1: SOAR Architecture & Integration:** Deploying n8n on Docker, integrating Wazuh webhooks, enriching IoCs via AbuseIPDB/VirusTotal, dispatching interactive HTML alert cards to Telegram, and integrating Jira Cloud REST API v3. |
| [`Phase-5_Closed-Loop-Containment-and-Rollback.md`](Phase-5_Closed-Loop-Containment-and-Rollback.md) | **Part 2: Closed-Loop Containment & Rollback:** **1-Click Safe Host Isolation** (preserving ports 5985 & 1514/1515), malicious process termination, Registry persistence cleanup, and **1-Click Rollback restoring network access within 5 seconds**. |
