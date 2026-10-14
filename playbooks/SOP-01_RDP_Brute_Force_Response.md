# 📋 INCIDENT RESPONSE PLAYBOOK: RDP PASSWORD BRUTE-FORCE ATTACK (SOP-01)
> **Playbook Code:** SOP-SOC-IR-001  
> **MITRE ATT&CK Technique:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) / [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)  
> **Associated Alert:** Wazuh Rule ID `100001` (Windows Brute Force Attack Detected - Level 12)  
> **Target Audience:** SOC Analyst L1/L2, Incident Response Team, Windows System Admin  

---

## 🎯 1. OVERVIEW & OBJECTIVES
This procedure provides detailed instructions for verification, severity classification, immediate containment, and remediation when the Wazuh SIEM system detects aggressive password brute-force behavior targeting the Remote Desktop service (RDP - Port 3389) on Windows Endpoint servers/workstations.

---

## 🔍 2. PHASE 1: RECEPTION & INITIAL TRIAGE (IDENTIFICATION & TRIAGE - SOC L1)

Upon receiving Alert **Rule 100001** from the Wazuh Dashboard or Telegram channel, the L1 Analyst conducts an investigation following these 3 steps:

### Step 2.1: Gather Alert Information from Wazuh
Extract the core data fields from the JSON log:
* `data.win.eventdata.targetUserName`: Targeted account name (e.g., `testw`, `administrator`, `admin`).
* `data.win.eventdata.ipAddress`: Source IP address launching the attack (e.g., `192.168.71.130`).
* `data.win.eventdata.logonType`: Logon type (`10` = RemoteInteractive / RDP).
* `data.win.eventdata.status` / `subStatus`: Windows authentication error codes:
  * `0xC000006A`: Incorrect password (User name is correct, but password is bad).
  * `0xC0000064`: Account does not exist on the system (User name does not exist).
  * `0xC0000234`: Account locked out due to exceeding threshold (User account currently locked out).

### Step 2.2: Distinguish Actual Attack vs False Positive

| Classification Criteria | Legitimate User Forgot Password | Automated Attack (Hydra, xfreerdp, Medusa) |
| :--- | :--- | :--- |
| **Velocity** | 2 – 5 failures within 1 – 2 minutes. | **> 10 attempts in just a few seconds** (high frequency/rapid succession). |
| **Username Diversity** | Only mistypes their own single individual account. | Scans across numerous default accounts (`admin`, `root`, `user`, `administrator`). |
| **Source IP Location** | Originates from a familiar internal departmental subnet. | Originates from an unfamiliar IP subnet, external workstation, or testing VM (`192.168.71.130`). |
| **SubStatus Error Code** | Mostly `0xC000006A` (bad password). | Consecutive occurrences of multiple `0xC0000064` errors (guessing usernames from wordlist). |

### Step 2.3: MOST CRITICAL CHECK — Did the Attacker Compromise the System?
One of the most critical mistakes of a SOC Analyst is merely reporting "Brute Force blocked" without verifying whether the attacker successfully guessed the password.

* **Query on Wazuh Dashboard (Discover) or Windows Event Viewer:**
  Search for **Event ID 4624 (Successful Logon)** occurring immediately after the sequence of Event 4625 logs from the same IP:
  ```powershell
  # Run a quick check on Windows via WinRM/PowerShell:
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-30)} | Where-Object { $_.Properties[18].Value -eq '192.168.71.130' -and $_.Properties[8].Value -eq 10 }
  ```
* **Risk Assessment:**
  * **If Event 4624 Type 10 IS PRESENT:** 🚨 **RED ALERT (Severity P1 - Critical)**. The attacker has seized control of the host! Immediately transition to the malware response and deep intrusion investigation procedure.
  * **If Event 4624 IS ABSENT:** ⚠️ **Severity P3 - Medium** (if Active Response successfully blocked the IP) or **Severity P2 - High** (if the IP has not been blocked yet).

---

## 🛡️ 3. PHASE 2: INCIDENT CONTAINMENT (CONTAINMENT - SOC L2)

### Step 3.1: Verify Automated Active Response Status
Check whether the Wazuh Agent has applied the block rule via `netsh.exe` :
```powershell
# Check Agent active response log:
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 5

# Check effective Windows firewall rules:
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
```

### Step 3.2: Manual Intervention (Fallback when Active Response Fails)
If Active Response fails to trigger or firewall rules conflict for any reason:

1. **Immediately block the attacking IP via PowerShell:**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_EMERGENCY_BLOCK_192.168.71.130" -Direction Inbound -Action Block -RemoteAddress 192.168.71.130
   ```
2. **If the attacker has an active RDP session:**
   ```cmd
   :: List active connected RDP sessions:
   qwinsta
   
   :: Disconnect and immediately terminate the attacker session (e.g. session ID = 2):
   rwinsta 2
   ```
3. **Isolate the computer from the local network (Network Isolation):**
   If the host is suspected of being fully compromised, disconnect the network connection immediately to prevent Lateral Movement:
   ```powershell
   # Disable network adapter on Windows:
   Disable-NetAdapter -Name "Ethernet0" -Confirm:$false
   ```

---

## 🧹 4. PHASE 3: THREAT ERADICATION (ERADICATION)

1. **Lock and disable the targeted account:**
   If the targeted account (e.g. `testw`) is at risk of weak credential exposure:
   ```powershell
   # Temporarily disable account:
   Disable-LocalUser -Name "testw"
   
   # Revoke all login tokens and reset password to a strong random string:
   $newPass = [System.Web.Security.Membership]::GeneratePassword(16, 4)
   Set-LocalUser -Name "testw" -Password ($newPass | ConvertTo-SecureString -AsPlainText -Force)
   ```
2. **Audit for post-compromise anomalous behavior (if breach is suspected):**
   * **Sysmon Event ID 1 (Process Create):** Check whether any suspicious process was spawned from `rdpclip.exe` or `userinit.exe` during the attack timeframe.
   * **Check for stealthily created new accounts (Event ID 4720):**
     ```powershell
     Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=(Get-Date).AddHours(-2)}
     ```
   * **Check for suspicious listening network ports (Backdoor):**
     ```powershell
     netstat -ano | Select-String "LISTENING"
     ```

---

## 🔄 5. PHASE 4: SYSTEM RECOVERY & VALIDATION (RECOVERY)

1. Unlock the user account after issuing a new complex password (minimum 12 characters, including uppercase, lowercase, numbers, and special characters).
2. Re-enable the network adapter (if previously isolated):
   ```powershell
   Enable-NetAdapter -Name "Ethernet0" -Confirm:$false
   ```
3. Verify service integrity: Run the infrastructure health check script:
   ```powershell
   python tests/e2e/lab_health.py
   ```
4. Establish Enhanced Monitoring for that IP and User for the **subsequent 48 hours**.

---

## 🛡️ 6. PHASE 5: LESSONS LEARNED & SYSTEM HARDENING

To completely mitigate future RDP password brute-force attack risks, apply the following technical hardening measures:

### Measure 1: Enforce Network Level Authentication (NLA)
NLA requires users to authenticate their identity with the operating system before the RDP graphical session is established, preventing automated scanning tools from transmitting data directly to the OS.
```powershell
# Enable NLA via PowerShell:
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(1)
```

### Measure 2: Configure Account Lockout Policy
Configure automatic account lockout after 5 failed login attempts within 15 minutes:
```cmd
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

### Measure 3: Change Default RDP Port (Security through Obscurity)
Change the RDP listening port from `3389` to a non-standard port (e.g., `33890`) to avoid broad automated scans:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value 33890
New-NetFirewallRule -DisplayName "RDP_Custom_Port_33890" -Direction Inbound -LocalPort 33890 -Protocol TCP -Action Allow
```

### Measure 4: Restrict RDP Access by IP (IP Whitelisting)
Allow RDP connections only from designated management hosts or internal VPN IP ranges, blocking all direct connections from the Internet.
```powershell
Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -RemoteAddress "192.168.71.1/24"
```
