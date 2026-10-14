# 🔄 Phase 6: DevSecOps CI/CD Pipeline (GitHub Actions)

Directory containing technical reports and proof-of-concept evidence for **Phase 6**, implementing an enterprise-grade automated CI/CD pipeline for detection engineering quality assurance.

---

## 📌 Main Technical Report
* **Detailed Document:** [`Phase-6_Detection-Engineering-CICD-Pipeline.md`](Phase-6_Detection-Engineering-CICD-Pipeline.md)
* **Contents:**
  - Design of a GitHub Actions workflow running across a multi-version Python environment (`3.10`, `3.11`).
  - Suite of automated test cases (Pytest Unit Checks): validating XML syntax, Rule ID uniqueness, severity levels (0–16), MITRE ATT&CK technique formatting, Regex/PCRE2 compilation safety, and Zero Secret Leakage compliance.
  - Automatically blocks violating commits or Pull Requests prior to production deployment.
