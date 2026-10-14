# 🏛️ Architecture & Network Topology

Directory storing the overall architecture diagrams, network connectivity model, and automation data flow of the **Wazuh SOC & SOAR Lab** system.

---

## 📌 Documentation & Diagrams Catalog

| File | Format | Functional Description |
| :--- | :---: | :--- |
| `Deployment and Containerization Architecture.png` | Image (PNG) | Infrastructure deployment diagram of 3 independent virtual machines, Docker container architecture of Wazuh Cluster (Manager, Indexer, Dashboard) and n8n SOAR. |
| `Detection Pipeline & Active Response Sequence.png` | Image (PNG) | Sequence Diagram describing the log ingestion flow from Endpoint Sysmon/Suricata $\rightarrow$ Wazuh rule analysis $\rightarrow$ Active Response trigger $\rightarrow$ Dispatch to n8n $\rightarrow$ Telegram ChatOps. |

---

## 🌐 Node Network Specifications (Lab IP Map)
* **Wazuh SIEM & SOAR Server:** `192.168.71.128` (Ubuntu Server 22.04 LTS)
* **Windows Endpoint Target:** `192.168.71.129` (Windows 10 Pro - Wazuh Agent & Sysmon)
* **Kali Attacker Node:** `192.168.71.130` (Kali Linux Rolling)
