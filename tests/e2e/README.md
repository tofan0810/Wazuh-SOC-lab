# Phase 4 Automation

### 1. Run static tests on the main machine:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Run the three-VM health check:

```powershell
python tests/e2e/lab_health.py
```

The health check uses SSH for Kali/Ubuntu and WinRM for Windows.

### 3. Scenario 1: Controlled RDP Brute Force (T1110)

Runs the automated RDP attack, Windows Event 4625 detection, Wazuh Rule 100001 correlation, and Active Response verification:

```powershell
python -m pip install -r requirements-e2e.txt
python tests/e2e/scenario_rdp_bruteforce.py --execute
```

### 4. Scenario 2: Controlled Web LFI / Directory Traversal (T1190)

Runs the automated Apache LFI exploitation, Custom Decoder `web-access-lfi`, Wazuh Rule 100002 correlation, and Active Response verification:

```powershell
python tests/e2e/scenario_lfi_web.py --execute
```

### 5. Scenario 3: Full Kill Chain Automation (T1059.001, T1548.002, T1547.001, T1003.001)

Runs the automated multi-stage attack and detection verification across PowerShell execution (Rule 100004), UAC bypass (Rule 100007), persistence registry run keys (Rule 100006), and LSASS memory access (Rule 100005) with Sysmon telemetry:

```powershell
python tests/e2e/scenario_full_killchain.py --execute
```

### 6. SOAR & Webhook Automation Test (Phase 5)

Verifies the end-to-end integration between Wazuh, n8n webhook ingest, AbuseIPDB threat intel, and Telegram ChatOps callbacks:

```powershell
python tests/e2e/test_soar_webhook.py
```

### 7. Scenario 4: Suricata NIDS & XDR Network Threat Verification (Phase 9)

Simulates network reconnaissance and web exploitation from Kali Attacker (Nmap SYN scan, HTTP directory traversal, automated scanner probe), verifying packet capture via Suricata NIDS, EVE JSON ingestion into Wazuh SIEM, and XDR cross-telemetry correlation:

```powershell
python tests/e2e/scenario_nids_suricata.py
```

> **Note:** The default WinRM user is `socrunner` (Local Administrator on Windows Victim). For Scenario 1, the default RDP victim user is `testw`. Ensure the Apache service (XAMPP) is running on the Windows victim before triggering Scenario 2.
