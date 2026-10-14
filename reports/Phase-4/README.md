# 🔄 Phase 4: Regression Test Automation

Directory containing documentation and experimental evidence for **Phase 4**, focusing on automating the regression testing lifecycle for attack scenarios and validating SIEM rule set accuracy.

---

## 📌 Main Technical Report
* **Detailed Report:** [`Phase-4_Regression-Test-Automation.md`](Phase-4_Regression-Test-Automation.md)
* **Summary:**
  - Designing the Python automated E2E testing suite (`tests/e2e/`).
  - Verifying connectivity and readiness across all 3 virtual machines (`lab_health.py`).
  - Automating remote attack execution via SSH/WinRM, tracking `alerts.json` log streams, and confirming 100% test pass rates.
  - Automated environment eradication and cleanup mechanisms post-test.
