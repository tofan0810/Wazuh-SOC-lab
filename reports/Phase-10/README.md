# 🍯 Phase 10: Deception Honeypots & Automated DFIR Evidence Collection

Directory containing technical reports and proof-of-concept evidence for **Phase 10**, upgrading the defense posture from reactive to **Active Defense** using deception technology and automated digital forensics preservation.

---

## 📌 Main Technical Report
* **Detailed Document:** [`Phase-10_Deception-Technology-Honeypots.md`](Phase-10_Deception-Technology-Honeypots.md)
* **Contents:**
  - Deployment of a 3-tier deception grid: Canary Honey-File (Windows SACL Event ID 4663), Honey-Account `backup_admin` (Event ID 4625), and Network Service Decoy (TCP Port 21 FTP Listener).
  - Achieves **Zero False Positive (0% false alarm rate)** standards, triggering immediate automated attacker IP containment.
  - **Automated Live DFIR Preservation** module: automatically captures process RAM mini-dumps, `netstat` socket tables, active sessions, and binary `.evtx` logs, compressing them into a `.zip` archive and attaching it directly to a **Jira Cloud Incident Ticket**.
