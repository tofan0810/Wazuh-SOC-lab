# ⚙️ Operations & Automation Scripts

This directory houses Python automation scripts for operations, configuration management, and detection rule compilation within the **Wazuh SOC Lab** ecosystem.

---

## 📌 Script Directory

| Script | Purpose & Functionality | Usage |
| :--- | :--- | :--- |
| `sync_env.py` | **Environment Synchronization:** Parses `.env` variables, validates API connectivity and credentials (Telegram, Jira, AbuseIPDB, VirusTotal), and deploys configuration changes to Wazuh Manager & n8n. | `python scripts/sync_env.py`<br/>*(or run `sync_env.bat`)* |
| `import_dashboard.py` | **1-Click Dashboard Import:** Ingests all 9 Saved Objects (`.ndjson`) into OpenSearch Dashboards (Wazuh Dashboard Port 443) via REST API in under 1.5 seconds. | `python scripts/import_dashboard.py` |
| `sigma_compiler.py` | **SigWaz Compiler Engine:** Compiles Sigma YAML detection rules into standard Wazuh XML syntax, automatically generates hierarchical suppression rules (`level="0"`), and validates rule parity (`--check`). | `python scripts/sigma_compiler.py`<br/>`python scripts/sigma_compiler.py --check` |
