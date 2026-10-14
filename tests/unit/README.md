# 🧪 Detection Engineering Unit Test Suite

> **Subsystem:** Unit Testing & Detection-as-Code Quality Assurance (Detection-as-Code QA)  
> **Target Files:** `manager/rules/local_rules.xml`, `manager/rules/local_decoder.xml`, `manager/docker/ossec.conf`, `endpoint/config/sysmon-config.xml`, `manager/dashboard/*.ndjson`, `manager/suricata/*`

---

## 📌 Overview
This directory contains the automated unit testing suite safeguarding the Wazuh SIEM ecosystem against XML syntax errors, conflicting Rule ID identifiers, invalid regular expressions (Regex), and security policy regressions. This test suite is automatically executed by **GitHub Actions CI/CD** (`.github/workflows/test.yml`) on every commit and Pull Request.

---

## 🛡️ Directory of 22 Automated Checks

| No. | Test Method | Objective & Verification Scope |
| :---: | :--- | :--- |
| 1 | `test_xml_files_well_formed` | Validates standard XML well-formedness of `local_rules.xml`, `local_decoder.xml`, `ossec.conf`, and `sysmon-config.xml` to prevent `wazuh-analysisd` service crashes. |
| 2 | `test_rule_ids_are_unique_and_valid` | Ensures uniqueness across all custom Rule IDs within the compliant custom range (`>= 100000`). |
| 3 | `test_rule_levels_in_valid_range` | Validates that severity levels adhere strictly to Wazuh standard ranges (`0–16`). |
| 4 | `test_mitre_attack_id_format` | Validates MITRE ATT&CK taxonomy format (`Txxxx` or sub-technique `Txxxx.xxx`). |
| 5 | `test_brute_force_rule` | Rule 100001 (Level 12, frequency=5, timeframe=60, if_matched_sid=60122, MITRE T1110). |
| 6 | `test_lfi_rule` | Rule 100002 (Level 10, if_sid=31100, MITRE T1190, Directory Traversal pattern filtering). |
| 7 | `test_lfi_decoder_extracts_url` | Decoder `web-access-lfi` correctly parses and extracts the `url` field from Apache Access Logs. |
| 8 | `test_killchain_rules_present_and_configured` | Complete coverage across 4 MITRE Kill Chain stages: Rule 100004 (T1059.001), 100007 (T1548.002), 100006 (T1547.001), 100005 (T1003.001). |
| 9 | `test_hierarchical_suppression_rules` | Hierarchical suppression rules (Rule 100008, 100009, 100010) configured at Level 0, referencing correct parent rules, enforcing strict AND logic for WinRM `socrunner`. |
| 10 | `test_decoder_and_rule_regexes_compile` | All regexes within `<decoder>` and `<field>` (PCRE2) compile cleanly without raising `re.error`. |
| 11 | `test_single_n8n_integration_block` | Strictly one `<integration>` block for `custom-n8n` webhook declared in `ossec.conf`. |
| 12 | `test_zero_secret_leakage_in_templates` | Verifies that `.env.example` and configuration templates do not leak live secrets (VirusTotal, Telegram, Jira, Passwords). |

---

## 🚀 Execution Instructions

### 1. Using Built-in unittest runner (No external dependencies required):
```powershell
python -m unittest discover -s tests/unit -v
```

### 2. Using pytest with code coverage analysis (Coverage):
```powershell
pytest tests/unit/ -v --cov=tests/unit --cov-report=term-missing
```

### 3. CI/CD Automation via GitHub Actions:
Every push or pull request to branch `main` touching `manager/`, `endpoint/`, or `tests/` automatically triggers the `.github/workflows/test.yml` workflow on a cloud-hosted Ubuntu runner.
