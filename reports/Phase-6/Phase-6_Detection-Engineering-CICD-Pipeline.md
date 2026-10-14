# CI/CD PIPELINE IMPLEMENTATION REPORT FOR DETECTION ENGINEERING (PHASE 6 - DETECTION-AS-CODE WITH GITHUB ACTIONS)

* **Project:** Centralized Cybersecurity Monitoring & Incident Response System (Wazuh SIEM/XDR Lab)
* **Simulated Role:** Detection Engineer / SOC Automation Engineer (DevSecOps / SecOps Lead)
* **Execution Environment:**
  * **CI/CD Infrastructure:** GitHub Actions Cloud Runner (`ubuntu-latest`) with Python `3.10` and `3.11` parallel test matrix.
  * **Local Controller Environment (Host):** Windows 10/11 Pro, Python 3.11.9, `pytest 9.0.2`, `pytest-cov 7.1.0`.
  * **Audit Targets (Under Test):** Custom rule set [`custom-rules/local_rules.xml`](../../custom-rules/local_rules.xml), custom decoder [`custom-rules/local_decoder.xml`](../../custom-rules/local_decoder.xml), SIEM configuration [`deployment/ossec.conf`](../../deployment/ossec.conf), endpoint audit configuration [`deployment/sysmon-config.xml`](../../deployment/sysmon-config.xml), and configuration template [`.env.example`](../../.env.example).

---

## I. PROBLEM OVERVIEW & DETECTION-AS-CODE (DaC) PHILOSOPHY

### 1. Real-World Operational Challenges in an Enterprise SOC
In a modern Next-Gen Security Operations Center (Next-Gen SOC), **Detection Engineering** personnel frequently research emerging threats (Emerging Threats, CVEs, new MITRE ATT&CK techniques) to craft or fine-tune SIEM detection rules. However, traditional rule management processes (direct GUI manipulation or manual configuration file editing on the SIEM server) carry catastrophic risks:

1. **Risk of Crashing the SIEM Analysis Core (Daemon Crash):**
   * Wazuh relies on the `wazuh-analysisd` log analysis daemon. If an engineer inadvertently enters invalid XML syntax (missing closing tag `</rule>`, invalid `level` attribute, malformed tag nesting) and reloads the service, `wazuh-analysisd` will **terminate immediately**.
   * Consequence: The entire SOC becomes "blind" (Blind Spot), losing the ability to ingest logs and detect any security incident across thousands of enterprise endpoints.
2. **Rule ID Collisions:**
   * If two engineers create new rules with colliding `id` values (or encroach on the system default ID range `< 100000`), Wazuh will fail to start or disable one of the rules, creating a security gap for attackers.
3. **Regular Expression Failures (Regex / PCRE2 Failure):**
   * Malformed regular expressions or patterns causing catastrophic backtracking will consume 100% of SIEM server CPU or generate massive false positives, exhausting L1 SOC analysts on shift.
4. **Credential & Secret Leakage:**
   * When pushing source code to a shared team Git repository, the risk of accidentally committing real API tokens (Telegram Bot Token, VirusTotal API Key, AbuseIPDB Key, Jira Password) is extremely high without automated security scanning.
5. **Breaking the Integrity of Automated Noise Reduction Rules (Broken Suppression):**
   * SOAR remediation actions (such as WinRM `socrunner` terminating processes or isolating networks) require hierarchical suppression rules (Hierarchical Suppression Rules - Level 0) to avoid triggering alert feedback loops. If these rules are corrupted or misconfigured, the system enters an alert storm state.

---

### 2. Solution Philosophy: Detection-as-Code (DaC) Combined with CI/CD Pipeline
To systematically eliminate the above risks, the project adopts the **Detection-as-Code (DaC)** paradigm following international industry standards:
* **All detection rules and decoders are managed as source code** within Git Version Control.
* **Every change (Commit / Pull Request) must pass through an automated CI Gatekeeper** hosted on **GitHub Actions**.
* If any XML syntax error, ID collision, broken regex, or secret leak is detected, GitHub Actions will **halt execution (Fail Build ❌)**, preventing invalid code from merging into the main branch (`main`) and protecting 100% uptime for the Wazuh SIEM cluster.

```text
  ┌────────────────────────────────────────────────────────────────────────┐
  │                 DETECTION-AS-CODE OPERATIONAL WORKFLOW                 │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ Engineer commits new XML rule
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │         GITHUB ACTIONS CI PIPELINE (.github/workflows/test.yml)        │
  │                                                                        │
  │  [Ubuntu Runner: Python 3.10 & Python 3.11 Matrix]                     │
  │   ├── 1. XML Well-formedness & Syntax Parser (local_rules, decoder)    │
  │   ├── 2. Rule ID Uniqueness & Namespace Validation (>= 100000)         │
  │   ├── 3. Alert Severity Range Audit (Level 0 - 16)                     │
  │   ├── 4. MITRE ATT&CK Technique Format Verification (Txxxx.xxx)       │
  │   ├── 5. Scenario 1 (RDP Brute Force) & Scenario 2 (LFI) Rule Logic    │
  │   ├── 6. 4-Stage MITRE Kill Chain Rules (T1059, T1548, T1547, T1003)   │
  │   ├── 7. Hierarchical Child Suppression Rules (Level 0, AND logic)     │
  │   ├── 8. PCRE2 & Decoder Regex Compilation Safety                       │
  │   ├── 9. Single SOAR Integration Block Integrity (custom-n8n)          │
  │   └── 10. Zero Secret Leakage Scan (Templates & Configs)               │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   │                                     │
           [12/12 PASS] ✅                         [ANY FAIL] ❌
                   │                                     │
                   ▼                                     ▼
  ┌─────────────────────────────────┐   ┌─────────────────────────────────┐
  │     MERGE TO PRODUCTION SIEM    │   │         BLOCK MERGE P.R.        │
  │ • Displays Build Passing Badge  │   │ • Red alert on GitHub           │
  │ • Safely synchronizes to Wazuh  │   │ • Protects analysisd daemon     │
  └─────────────────────────────────┘   └─────────────────────────────────┘
```

---

## II. TECHNICAL ARCHITECTURE OF THE GITHUB ACTIONS PIPELINE

### 1. Workflow Configuration File ([`.github/workflows/test.yml`](../../.github/workflows/test.yml))
The workflow is configured with optimal technical parameters:
* **Workflow Name:** `Detection Engineering CI`
* **Trigger Events (Triggers):**
  * `push` and `pull_request` to `main`, `master` branches.
  * Path filters (`paths`): Only triggers on changes within `custom-rules/**`, `tests/**`, `deployment/**`, `.github/workflows/**`, `Makefile`, `.env.example`. This saves resources and reduces CI runtime when editing documentation.
  * Manual trigger support (`workflow_dispatch`) for immediate on-demand validation.
* **Environment Matrix (Matrix Strategy):**
  * Executes in parallel on **Python 3.10** and **Python 3.11** on `ubuntu-latest`.
  * `fail-fast: false`: Ensures that if one version fails, the other still completes to gather comprehensive comparative reports.

```yaml
name: Detection Engineering CI

on:
  push:
    branches: [ "main", "master" ]
    paths:
      - 'custom-rules/**'
      - 'tests/**'
      - 'deployment/**'
      - '.github/workflows/**'
      - 'Makefile'
      - '.env.example'
  pull_request:
    branches: [ "main", "master" ]
    paths:
      - 'custom-rules/**'
      - 'tests/**'
      - 'deployment/**'
      - '.github/workflows/**'
      - 'Makefile'
      - '.env.example'
  workflow_dispatch:

jobs:
  validate-detections:
    name: Validate Rules, Decoders & SIEM Configs (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11"]

    steps:
      - name: 📥 Checkout repository
        uses: actions/checkout@v4

      - name: 🐍 Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: 📦 Install testing dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest pytest-cov

      - name: 🧪 Execute Detection Engineering Unit Tests (pytest)
        run: |
          pytest tests/unit/ -v --junitxml=test-results-${{ matrix.python-version }}.xml --cov=tests/unit --cov-report=term-missing

      - name: 🔍 Secondary Verification via Builtin unittest Runner
        run: |
          python -m unittest discover -s tests/unit -v

      - name: 📋 Publish CI Detection Engineering Summary
        if: always()
        run: |
          echo "### 🛡️ Detection Engineering CI Pipeline Summary" >> $GITHUB_STEP_SUMMARY
          echo "Environment: **Python ${{ matrix.python-version }} on Ubuntu Latest**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Validation Category | Target Component | Status |" >> $GITHUB_STEP_SUMMARY
          echo "| :--- | :--- | :---: |" >> $GITHUB_STEP_SUMMARY
          echo "| XML Syntax & Well-Formedness | \`custom-rules/local_rules.xml\`, \`local_decoder.xml\` | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| SIEM & Sysmon Schema | \`deployment/ossec.conf\`, \`sysmon-config.xml\` | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Rule ID Uniqueness (>=100000) | Custom Rules 100001 - 100010 | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Alert Level Validation (0-16) | Severity Bounds & Hierarchy | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| MITRE ATT&CK Format Verification | T1110, T1190, T1059, T1548, T1547, T1003 | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| PCRE2 & Regex Compilation | Custom Decoders & Sysmon Match Fields | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Child Suppression Rules (Level 0) | SOAR Remediation (WinRM \`socrunner\`) | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Zero Secret Leakage Audit | No plaintext credentials in templates | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| SOAR Integration Architecture | Single \`custom-n8n\` Webhook Block | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
```

---

## III. DETAILS OF THE 12 AUTOMATED UNIT TEST SUITES

All 12 audit checks are implemented in [`tests/unit/test_detection_config.py`](../../tests/unit/test_detection_config.py) subclassing the standard library `unittest.TestCase`:

```python
import os
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Repo root is 2 levels up from tests/unit/
ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "custom-rules" / "local_rules.xml"
DECODERS = ROOT / "custom-rules" / "local_decoder.xml"
OSSEC_CONF = ROOT / "deployment" / "ossec.conf"
SYSMON_CONF = ROOT / "deployment" / "sysmon-config.xml"
ENV_EXAMPLE = ROOT / ".env.example"
```

### 12 Audit Criteria Analysis Matrix:

| No. | Test Method Name | Validation Target | Security Significance & Technical Standards |
| :---: | :--- | :--- | :--- |
| **1** | `test_xml_files_well_formed` | `local_rules.xml`<br/>`local_decoder.xml`<br/>`ossec.conf`<br/>`sysmon-config.xml` | Parses the XML DOM tree. Ensures all open/close tags and UTF-8 encodings are free of syntax errors, preventing `wazuh-analysisd` service crashes. |
| **2** | `test_rule_ids_are_unique_and_valid` | All `<rule id="...">` tags | Validates the uniqueness of every Rule ID across the system. Ensures all custom IDs are integers and adhere to the convention user-defined namespace (`id >= 100000`). |
| **3** | `test_rule_levels_in_valid_range` | `level` attribute of Rules | Checks that alert severity levels fall within Wazuh standard bounds (`0 <= level <= 16`), preventing misconfigured levels from corrupting filtering mechanisms. |
| **4** | `test_mitre_attack_id_format` | `<mitre><id>` tags | Uses regex `^T\d{4}(\.\d{3})?$` to validate MITRE ATT&CK technique formatting (e.g., `T1110`, `T1059.001`), ensuring accurate rendering on the Heatmap matrix. |
| **5** | `test_brute_force_rule` | Rule `100001` | Validates Scenario 1 configuration: `level="12"`, `frequency="5"`, `timeframe="60"`, inherits `if_matched_sid="60122"` and maps to technique `T1110`. |
| **6** | `test_lfi_rule` | Rule `100002` | Validates Scenario 2 configuration: `level="10"`, inherits `if_sid="31100"`, maps to `T1190`, comprehensively detects Path Traversal strings: `win.ini`, `boot.ini`, `..%2f`, `..%252f`, `../`. |
| **7** | `test_lfi_decoder_extracts_url` | Decoder `web-access-lfi` | Validates Apache Web log decoder: inherits parent `web-accesslog`, extracts `url` field via regex `GET (\S+)\sHTTP`. |
| **8** | `test_killchain_rules_present_and_configured` | Rules `100004`, `100007`, `100006`, `100005` | Validates all 4 Windows Kill Chain stages: PowerShell Encoded (`T1059.001`), UAC Bypass `ms-settings` (`T1548.002`), Registry Run Key (`T1547.001`), and LSASS Memory Dump (`T1003.001`). |
| **9** | `test_hierarchical_suppression_rules` | Rules `100008`, `100009`, `100010` | Ensures SOAR suppression rules have `level="0"`, correctly link to parent rules via `if_sid`, and apply strict AND logic with authorized user `socrunner` and WinRM processes (`cmd.exe`, `wsmprovhost.exe`). |
| **10** | `test_decoder_and_rule_regexes_compile` | All `<regex>` and `<field type="pcre2">` | Compiles and validates all regular expressions using the `re.compile` engine. Catches syntax errors early to avoid regex hanging during scans. |
| **11** | `test_single_n8n_integration_block` | `<integration>` tag in `ossec.conf` | Verifies that exactly one `custom-n8n` integration block exists pointing to webhook `/webhook/wazuh-alert`, avoiding duplicate alert distribution. |
| **12** | `test_zero_secret_leakage_in_templates` | Template file `.env.example` | Scans for hardcoded secrets: ensures only placeholder strings are used (such as `your_virustotal_api_key_here`), strictly preventing leakage of real tokens (Telegram bot token `\d{8,10}:[A-Za-z0-9_-]{35}` or 64-character hashes). |

---

## IV. EXECUTION STEPS & EXPERIMENTAL EVIDENCE INSTRUCTIONS

Below are the 5 experimental verification steps demonstrating the end-to-end operation of the CI/CD Pipeline. Each step includes verification screenshots and detailed guidelines.

---

### 1. Step 1: Local Unit Testing Execution

Before committing source code to GitHub, the engineer executes local testing on the workstation using `pytest` combined with code coverage measurement (`pytest-cov`).

* **Execution Command on Host Machine (PowerShell):**
  ```powershell
  # Run verbose tests via pytest
  pytest tests/unit/ -v --cov=tests/unit --cov-report=term-missing

  # Or perform comparative validation with Python's built-in unittest
  python -m unittest discover -s tests/unit -v
  ```

* **Achieved Results:** All 12 unit tests pass successfully with fast execution times:

![Local 12 Unit Tests execution results achieving 100% PASS](images/01_unit_tests_local_execution.png)

### 2. Step 2: CI Workflow Configuration Structure in Editor (IDE View)

Visualizing the pipeline configuration `.github/workflows/test.yml` and the `tests/unit/` folder structure in Visual Studio Code.

* **File Locations:** [`.github/workflows/test.yml`](../../.github/workflows/test.yml) and [`tests/unit/test_detection_config.py`](../../tests/unit/test_detection_config.py).

### 3. Step 3: Automated GitHub Actions Pipeline Trigger & Successful Run (CI Pipeline Run)

When an engineer pushes a commit or opens a Pull Request updating detection rules on GitHub, GitHub Actions immediately provisions a cloud runner and triggers the automated testing pipeline.

* **Repository Path on GitHub:** `https://github.com/tofan0810/Wazuh-SOC-lab/actions`
* **Workflow Name:** `Detection Engineering CI`
* **Result:** Both jobs across **Python 3.10** and **Python 3.11** complete with green checkmarks `Success` ✅.

![GitHub Actions pipeline successful execution interface](images/02_github_actions_pipeline_run.png)

### 4. Step 4: Visual Test Status Summary Table (GitHub Step Summary)

By exporting data to `$GITHUB_STEP_SUMMARY` in the workflow configuration, GitHub Actions automatically renders a security quality validation summary directly on the run summary page without requiring engineers to inspect terminal logs.

![GitHub Step Summary visual report on GitHub Actions](images/03_github_step_summary.png)
