# 🧪 Test Automation Framework (Detection-as-Code)

This directory houses the project's comprehensive automated testing framework, encompassing **Unit Tests** within the CI/CD Pipeline and **End-to-End (E2E) Tests** executed against the live laboratory environment.

---

## 🗂️ Testing Framework Structure

| Subsystem | Path | Testing Objective |
| :--- | :--- | :--- |
| **Unit Testing (CI/CD)** | [`unit/`](unit/) | Executes 22 automated unit tests validating XML Rule syntax, Decoders, PCRE2 regex expressions, MITRE ATT&CK taxonomy mappings, and Zero Secret Leakage security standards. Integrated with GitHub Actions. |
| **End-to-End Testing (E2E)** | [`e2e/`](e2e/) | Automated attack simulation runners executing attacks from Kali Linux $\rightarrow$ Windows Endpoint $\rightarrow$ Wazuh SIEM $\rightarrow$ SOAR Telegram/Jira. Audits live real-world detection pipelines. |

---

## ⚡ Test Execution Commands
* **Run local unit tests:**
  ```powershell
  pytest tests/unit/ -v
  ```
* **Run 3-VM lab health check:**
  ```powershell
  python tests/e2e/lab_health.py
  ```
* **Run Full Kill Chain attack scenario:**
  ```powershell
  python tests/e2e/scenario_full_killchain.py --execute
  ```
