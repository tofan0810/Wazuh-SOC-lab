# 🌐 Phase 9: Deep Network Monitoring with Suricata NIDS (XDR Integration)

Directory containing technical reports and proof-of-concept evidence for **Phase 9**, expanding the architecture from SIEM/EDR to **XDR** by integrating the **Suricata 8.0.7 NIDS** network intrusion detection system.

---

## 📌 Main Technical Report
* **Detailed Document:** [`Phase-9_Suricata-NIDS-XDR-Integration.md`](Phase-9_Suricata-NIDS-XDR-Integration.md)
* **Contents:**
  - Installation and configuration of Suricata 8.0.7 Stable on Ubuntu Server, optimizing network interface `ens33` in Promiscuous mode.
  - Development of 4 practical Custom Signatures (`local.rules`): Nmap Stealth SYN Scan (SID 2000001), Web LFI on Wire (SID 2000002), Vulnerability Scanners (SID 2000003), RDP Flood (SID 2000004).
  - Integration of the EVE JSON stream (`eve.json`) into Wazuh Manager via `<localfile>` json and instant alert forwarding to n8n Telegram ChatOps.
