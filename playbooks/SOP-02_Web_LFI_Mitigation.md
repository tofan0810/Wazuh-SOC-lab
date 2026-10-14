# 📋 INCIDENT RESPONSE PLAYBOOK: WEB LFI / DIRECTORY TRAVERSAL EXPLOITATION (SOP-02)
> **Playbook Code:** SOP-SOC-IR-002  
> **MITRE ATT&CK Technique:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)  
> **Associated Alert:** Wazuh Rule ID `100002` (WARNING: Local File Inclusion / Directory Traversal Attempt Detected - Level 10)  
> **Target Audience:** SOC Analyst L1/L2, Web Security Engineer, System/DevOps Admin  

---

## 🎯 1. OVERVIEW & OBJECTIVES
This procedure provides standard response steps when the Wazuh SIEM system detects an attacker sending **Local File Inclusion (LFI)** or **Directory Traversal** (`../`, `..%2f`, `..%252f`) exploit vectors targeting an Apache Web Server (XAMPP) on a Windows host to read sensitive operating system files (`win.ini`, system configurations) or attempting to escalate to Remote Code Execution (**RCE**).

---

## 🔍 2. PHASE 1: RECEPTION & INITIAL TRIAGE (IDENTIFICATION & TRIAGE - SOC L1)

### Step 2.1: Extract Alert Information from Wazuh
Upon receiving Alert **Rule 100002**, extract the critical data fields:
* `data.srcip`: Attacker IP address (e.g., `192.168.71.130`).
* `data.url`: Full URL path containing the malicious payload string (e.g., `/index.php?page=../../../../Windows/win.ini` or `..%252f`).
* `data.id`: HTTP Status Code returned by Apache (e.g., `200`, `403`, `404`).

### Step 2.2: Impact Analysis
Analyze the HTTP Status Code value to determine attack success:

* **Case 1 — HTTP Code `200 OK` (Extremely Dangerous - Severity P1/P2):**
  * The Web Server received the parameter, executed the `include()` function, and **successfully read** sensitive files, returning them to the attacker's browser.
  * *Action:* Escalate severity to **P1 - Critical**, immediately hand off to L2 to conduct data leak audit and Web Shell inspection.
* **Case 2 — HTTP Code `404 Not Found` or `403 Forbidden` (Severity P3 - Medium):**
  * The attacker is fuzzing / probing payloads or attempting to read a non-existent file / a file blocked by OS file permissions.
  * The attacker has not obtained data yet, but is actively conducting reconnaissance.
* **Case 3 — Bypass Technique:**
  * Verify whether the URL contains single encoding (`%2f`) or double encoding (`%252f`). If present, this is a clear indication of a targeted attack attempting to evade WAF/IDS inspection.

---

## 🛡️ 3. PHASE 2: INCIDENT CONTAINMENT (CONTAINMENT - SOC L2)

### Step 3.1: Verify Wazuh Active Response Status
Confirm whether the Wazuh Agent has blocked the attacker IP on Windows Defender Firewall:
```powershell
# Check Active Response log:
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 10 | Select-String "100002"

# Check firewall rules:
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
```

### Step 3.2: Emergency Intervention if Active Response Has Not Blocked
1. **Block source IP on Windows Firewall:**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_BLOCK_LFI_ATTACKER_192.168.71.130" -Direction Inbound -Action Block -RemoteAddress 192.168.71.130
   ```
2. **If widespread active exploitation is suspected:**
   Temporarily halt the Web application to isolate and protect sensitive data:
   ```cmd
   :: Immediately stop Apache service from command line:
   C:\xampp\apache\bin\httpd.exe -k stop
   ```

---

## 🔬 4. PHASE 3: DEEP INVESTIGATION & WEB SHELL AUDIT (INVESTIGATION & ERADICATION)

An LFI attack is often merely a stepping stone. Attackers will attempt to escalate LFI into **RCE (Remote Code Execution)** via **Log Poisoning** (poisoning Apache access logs) or uploading a Web Shell.

### Step 4.1: Use Sysmon Telemetry to Detect RCE
This is where Sysmon demonstrates significant advantage over standard web logs:

1. **Check for Anomalous Child Processes (Sysmon Event ID 1 - Process Creation):**
   The Web Server process (`httpd.exe` or `php-cgi.exe`) must **NEVER** spawn system command-line processes.
   ```powershell
   # Search for events where Apache process calls CMD or PowerShell:
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-4)} | Where-Object {
       $_.Properties[21].Value -like "*httpd.exe*" -and ($_.Properties[4].Value -like "*cmd.exe*" -or $_.Properties[4].Value -like "*powershell.exe*" -or $_.Properties[4].Value -like "*whoami.exe*")
   }
   ```
   👉 *If found: Attacker has successfully executed remote code!*

2. **Check for New Files Created in Web Directory (Sysmon Event ID 11 - FileCreate):**
   Check whether Apache recently created any script file (`.php`, `.phtml`, `.exe`, `.bat`, `.ps1`) in the web directory:
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=(Get-Date).AddHours(-4)} | Where-Object {
       $_.Properties[4].Value -like "C:\xampp\htdocs\*" -and $_.Properties[4].Value -match "\.(php|phtml|exe|bat|ps1)$"
   }
   ```

### Step 4.2: Inspect for Log Poisoning in Apache Logs
Check whether the attacker injected malicious PHP code into User-Agent or URL strings to write into log files:
```powershell
Select-String -Path "C:\xampp\apache\logs\access.log" -Pattern "(<\?php|eval\(|system\(|passthru\()"
```

### Step 4.3: Eradicate Malicious Files
* If an unrecognized file is found in `C:\xampp\htdocs\`: Quarantine the file into `C:\Quarantine\` for malware analysis before deletion.
* Restart Apache after cleanup.

---

## 🛠️ 5. PHASE 4: SOURCE CODE REMEDIATION & RECOVERY (REMEDIATION & RECOVERY)

### Step 5.1: Patch Vulnerable PHP Source Code (Root Cause Fix)

#### ❌ Vulnerable Source Code (`C:\xampp\htdocs\index.php`):
```php
<?php
    // DANGEROUS: Directly includes parameter without input validation
    if (isset($_GET['page'])) {
        $file = $_GET['page'];
        include($file);
    }
?>
```

#### ✅ Remediated Secure Source Code (Whitelisting & Path Sanitization):
```php
<?php
    // WHITELIST: Allow only valid pages
    $allowed_pages = [
        'home'    => 'pages/home.php',
        'about'   => 'pages/about.php',
        'contact' => 'pages/contact.php'
    ];

    if (isset($_GET['page'])) {
        $page = $_GET['page'];
        
        // Strict check: Only load file if present in whitelist
        if (array_key_exists($page, $allowed_pages) && file_exists($allowed_pages[$page])) {
            include($allowed_pages[$page]);
        } else {
            http_response_code(404);
            echo "<h1>404 - Requested page does not exist!</h1>";
        }
    } else {
        include('pages/home.php');
    }
?>
```

### Step 5.2: Restart and Verify Service
1. Save the remediated source code file.
2. Restart Apache service:
   ```cmd
   C:\xampp\apache\bin\httpd.exe -k restart
   ```
3. Rerun SOC automated test scenario to confirm the vulnerability is completely resolved:
   ```powershell
   python tests/e2e/scenario_lfi_web.py --execute
   ```

---

## 🛡️ 6. PHASE 5: LESSONS LEARNED & HARDENING (HARDENING)

### Measure 1: Restrict File Access Scope Using `open_basedir` in `php.ini`
Configure the `open_basedir` directive to strictly prevent PHP from accessing any file outside the web directory, even if directory traversal flaws remain in application code.

* Open file `C:\xampp\php\php.ini`:
  ```ini
  ; Restrict PHP access strictly to htdocs and temp directory
  open_basedir = "C:\xampp\htdocs;C:\xampp\tmp"
  
  ; Disable remote file inclusion (prevent RFI - Remote File Inclusion)
  allow_url_fopen = Off
  allow_url_include = Off
  
  ; Hide PHP version and suppress system error disclosure to screen
  expose_php = Off
  display_errors = Off
  log_errors = On
  ```

### Measure 2: Run Apache Under Least Privilege Service Account
Never run Apache under the Administrator account. Create a dedicated service account (`svc_apache`) with read-only permissions to `htdocs` and no read access to system directories such as `C:\Windows`.

### Measure 3: Deploy Web Application Firewall (WAF)
Integrate **ModSecurity** module or a Reverse Proxy (Nginx/Cloudflare) in front of the Web server to automatically detect and drop `../` and `%252f` strings at the network layer before packets reach the Apache application layer.
