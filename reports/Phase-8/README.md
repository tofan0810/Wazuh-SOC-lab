# 📜 Phase 8: Detection-as-Code with Sigma Rules (SSOT)

Directory containing technical reports for **Phase 8**, standardizing the entire detection ruleset into the open-standard **Sigma Rules** language following the Single Source of Truth (SSOT) architecture.

---

## 📌 Main Technical Report
* **Detailed Document:** [`Phase-8_Sigma-Rules-Integration.md`](Phase-8_Sigma-Rules-Integration.md)
* **Contents:**
  - Full conversion of all detection rules to Sigma YAML in [`custom-rules/sigma/`](../../custom-rules/sigma/).
  - Development of the **SigWaz Core Engine** compiler ([`scripts/sigma_compiler.py`](../../scripts/sigma_compiler.py)) for automated translation of Sigma to native Wazuh XML.
  - Automatic generation of hierarchical child suppression rules (`level="0"`) for the SOAR `socrunner` account.
  - **Zero-Drift Enforcement** mechanism integrated into the CI/CD Pipeline ensuring absolute synchronization between Sigma rule source code and production XML.
