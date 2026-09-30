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

> **Note:** The default WinRM user is `socrunner` (Local Administrator on Windows Victim). For Scenario 1, the default RDP victim user is `testw`. Ensure the Apache service (XAMPP) is running on the Windows victim before triggering Scenario 2.
