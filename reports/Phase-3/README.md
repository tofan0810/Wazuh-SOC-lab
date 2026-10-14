# ⚔️ Phase 3: Real-World Attack & Detection Scenarios

This directory contains detailed technical reports on the 3 simulated attack and detection scenarios executed from the Kali Linux host (`192.168.71.130`) targeting the Windows 10 Endpoint (`192.168.71.129`).

---

## 📌 Scenario Reports Directory

| Technical Report | MITRE Technique | Scenario Summary & Results |
| :--- | :---: | :--- |
| [`Phase-3_Scenario-1.md`](Phase-3_Scenario-1.md) | **T1110.001** | **RDP Brute Force:** Password spraying attack against RDP using `xfreerdp`. Captures Event ID 4625 via Rule 100001, automatically invoking `netsh` to block the attacker IP for 600s. |
| [`Phase-3_Scenario-2.md`](Phase-3_Scenario-2.md) | **T1190** | **Web LFI / Path Traversal:** Exploitation to read `win.ini` via Apache HTTP. Captured via Apache Access Log using Rule 100002, automatically blocking the attacker IP. |
| [`Phase-3_Scenario-3.md`](Phase-3_Scenario-3.md) | **T1059, T1548, T1547, T1003** | **Full Kill Chain:** 4-stage attack chain with Microsoft Sysmon (Base64 PowerShell, UAC Bypass ms-settings, Registry Run Key, and LSASS Memory Dump). Fully automated via `tests/e2e/scenario_full_killchain.py`. |
