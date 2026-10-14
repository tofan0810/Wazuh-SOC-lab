# 📜 Custom Rules & Decoders (Detection-as-Code)

This directory stores all custom decoders and detection rulesets for the Wazuh SIEM system, managed under the **Detection-as-Code** methodology.

---

## 🗂️ Directory Structure

```text
manager/rules/
├── sigma/             # Standardized Sigma YAML rule repository (Single Source of Truth - SSOT)
│   ├── win_*.yml      # Windows Endpoint detection rules (Sysmon & Security EVTX)
│   ├── net_*.yml      # Suricata NIDS network detection rules
│   └── README.md      # Detailed guidelines for Sigma detection standards
├── local_decoder.xml  # Custom decoder extracting Apache Web Server logs
└── local_rules.xml    # Integrated production XML ruleset (compiled automatically from Sigma YAML via SigWaz Compiler)
```

---

## 🔍 Core Detection Rule Range (Rule ID Namespace)

All custom rules are allocated within the reserved namespace `100000 - 100099`:
* **Rule 100001:** RDP Brute Force Detection (Event ID 4625)
* **Rule 100002:** Apache Web LFI / Path Traversal Detection
* **Rules 100004 - 100007:** Sysmon Multi-Stage Kill Chain (PowerShell, LSASS Dump, Run Key, UAC Bypass)
* **Rules 100008 - 100010:** Hierarchical Child Suppression Rules (Level 0) for SOAR account `socrunner`
* **Rules 100011 - 100013:** Suricata NIDS Events (Nmap SYN scan, LFI on wire, Scanners)
* **Rules 100014 - 100016:** Deception Canaries (Honey-File SACL 4663, Honey-Account 4625, Decoy 21)

---

## ⚡ Compilation & Anti-Drift Commands (Zero-Drift)
```powershell
# Verify synchronization between Sigma YAML and XML
python scripts/sigma_compiler.py --check

# Recompile from Sigma YAML to local_rules.xml
python scripts/sigma_compiler.py
```
