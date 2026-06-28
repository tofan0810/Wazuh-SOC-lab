# Attack Scenarios &amp; Real-World Detection (Phase 3)

## 🔹 Scenario 2: T1190 - Exploit Web Application Vulnerability (Local File Inclusion - LFI / Directory Traversal)

This scenario analyzes strange character syntax via advanced regular expressions, configuration technique to collect log files from third-party applications, write **Custom Decoders / Custom Rules** overriding the system, and integrate **Active Response** proactive defense solution of a Detection Engineer to protect outward-facing applications.

## Objective

* **Simulated objective (Attacker's Goal):** Attacker targets **Initial Access** tactic via **`T1190 - Exploit Public-Facing Application`** technique. By exploiting Local File Inclusion (LFI) / Directory Traversal vulnerability on outward-facing Apache web application, hacker attempts to secretly read sensitive configuration files (`win.ini`) of operating system to collect reconnaissance information.
* **System validation objective (SIEM/SOC Validation Goal):**
* Validate capability to monitor third-party application logs (XAMPP Apache) via Wazuh Agent's collection pipeline configuration.
* Evaluate sensitivity and accuracy of **Custom Decoder** in parsing complex URL parameters.
* Test **Custom Rule (PCRE2 Regex)** analysis capability against hacker evasion techniques, string obfuscation like simple encoding (`%2f`) and double encoding (`%252f`).
* Validate **Active Response** mechanism, activate Windows Defender Firewall (`netsh.exe`) to automatically isolate, block attacker source IP in real time.


## I. Configure Web Server and Log Collection Pipeline

### 1. Build LFI-Vulnerable Web Application Environment

To have web access log generation environment for Wazuh, a local Apache web server is configured via XAMPP package located at `C:\xampp` path on Windows 10 Victim machine to avoid UAC permission conflicts.

In `C:\xampp\htdocs\` source code directory, build source code file named `index.php` containing vulnerability without validating input parameters directly passed to system include function:

```php
&lt;?php
    // LFI Vulnerability: Directly take 'page' parameter from URL and pass to include without checking input
    if (isset($_GET['page'])) {
        $file = $_GET['page'];
        include($file);
    } else {
        echo "&lt;h1&gt;Welcome to My Public Web Application&lt;/h1&gt;";
    }
?&gt;
```

Activate **Apache** service from XAMPP Control Panel interface, ensure status switches to green and listens on default ports (80, 443).
![Apache service listening](images/phase3/scenario2/XAMPP-control-panel.png)

### 2. Direct Wazuh Agent to Collect Access Logs

To forward web event flow to central analysis, intervene in Agent's general configuration file with administrative privileges:

```cmd
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Add block defining monitoring of Apache's local log file to configuration section:

```xml
&lt;localfile&gt;
  &lt;log_format&gt;syslog&lt;/log_format&gt;
  &lt;location&gt;C:\xampp\apache\logs\access.log&lt;/location&gt;
&lt;/localfile&gt;
```

Perform Agent service restart from Administrator-privileged Command Prompt window to officially activate log push pipeline:

```cmd
NET STOP WazuhSvc &amp;&amp; NET START WazuhSvc
```

---

## II. Build Advanced LFI Detection Configuration on Wazuh Manager

### 1. Write Custom Decoder to Deeply Parse URL Parameters

By default Wazuh uses `web-accesslog` decoder set to process Apache logs. To specifically serve parsing raw payload behind `GET` method, proceed to extract and add custom decoder to `local_decoder.xml` file in Docker Container:

```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/decoders/local_decoder.xml ./local_decoder.xml.bak
```

Configure regular expression (Regex) to parse entire malicious parameter string assigned to dynamic data field:

```xml
&lt;decoder name="web-access-lfi"&gt;
  &lt;parent&gt;web-accesslog&lt;/parent&gt;
  &lt;regex&gt;GET (\S+)\sHTTP&lt;/regex&gt;
  &lt;order&gt;url&lt;/order&gt;
&lt;/decoder&gt;
```

### 2. Build Anti-Evasion Rule System (Double Encoding)

Hackers often use string obfuscation techniques like single encoding (`%2f`) or double encoding (`%252f`) to bypass regular rule sets. Proceed to copy rule file to add broad coverage filter:

```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml ./local_rules.xml.bak
```

```xml
&lt;group name="web,attack,lfi,"&gt;
  &lt;rule id="100002" level="10" overwrite="yes"&gt;
    &lt;if_sid&gt;31100&lt;/if_sid&gt;
    &lt;match&gt;win.ini|boot.ini|..%2f|..%252f|../&lt;/match&gt;
    &lt;description&gt;WARNING: Local File Inclusion (LFI) / Directory Traversal Attempt Detected on Windows Endpoint&lt;/description&gt;
    &lt;mitre&gt;
      &lt;id&gt;T1190&lt;/id&gt;
    &lt;/mitre&gt;
  &lt;/rule&gt;
&lt;/group&gt;
```

Synchronize modified configuration files back to Container, impose strict ownership for `wazuh` user and perform restart:

```bash
sudo docker cp ./local_decoder.xml.bak single-node-wazuh.manager-1:/var/ossec/etc/decoders/local_decoder.xml
sudo docker cp ./local_rules.xml.bak single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml

sudo docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/rules/local_rules.xml
sudo docker exec -it single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/rules/local_rules.xml

sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## III. Deploy Auto-Block IP Configuration (Active Response)

To upgrade system to automatic incident response capability (SOAR Capabilities), configure defense mechanism to instruct Agent to automatically hard-block attacker IP via Windows Defender Firewall.

### 1. Configure Active Response on Wazuh Manager

Extract central `ossec.conf` configuration file from Docker to Ubuntu workstation:

```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf ./ossec.conf.bak
```

Navigate to defense management section, add configuration block directly linking to just created Rule `100002`, using system `netsh` command with temporary isolation time of 10 minutes (600 seconds):

```xml
  &lt;active-response&gt;
    &lt;command&gt;netsh&lt;/command&gt;
    &lt;location&gt;local&lt;/location&gt; 
    &lt;rules_id&gt;100002&lt;/rules_id&gt;
    &lt;timeout&gt;600&lt;/timeout&gt; 
  &lt;/active-response&gt;
```

Push configuration file back to container and perform permission application, restart as above.
---

## IV. Validate Practicality and Collect Forensic Evidence (PoC)

&gt; ⚠️ **Practical note:** Before deploying test, access firewall interface `wf.msc` on Windows Victim machine to delete or deactivate (Disable) old blocking rules `Wazuh_ActiveResponse_...` left by Scenario 1 to free access permission for Kali machine.

### 1. Simulate LFI Exploit from Kali Linux Attacker Machine

From Kali Linux machine (`192.168.71.130`), proceed to launch exploit using raw reconnaissance parameter:

```bash
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=../../../../Windows/win.ini"
```

Result directly prints content of Windows security configuration file `win.ini` to screen, proving vulnerability was successfully exploited:

```text
; for 16-bit app support
[fonts]
[extensions]
```

Continue simulating sophisticated evasion technique with double encoding (Double Encoding) attack:

```bash
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=..%252f..%252f..%252fWindows%252fwin.ini"
```
![Attacker attacks victim machine](images/phase3/scenario2/kaliattack.png)
Although application returns error warning due to not automatically decoding string from `include()` function, however entire malicious trace string this trap was completely captured and fully recorded in Apache's `access.log` log file.
![Apache's log file](images/phase3/scenario2/access-log.png)
### 2. Validate Analysis Structure via `wazuh-logtest`

Call internal test tool on Ubuntu Manager to evaluate quality of malicious log line analysis:

```bash
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Paste actual double encoding log line recorded from Apache into it, result shows `Phase 2` successfully decoded and parsed malicious parameter to `url` field, and `Phase 3` filtered hit **Rule 100002** level 10:

```text
**Phase 2: Completed decoding.
	name: 'web-accesslog'
	url: '/index.php?page=..%252f..%252f..%252fWindows%252fwin.ini'

**Phase 3: Completed filtering (rules).
	id: '100002'
	level: '10'
	description: 'WARNING: Local File Inclusion (LFI) / Directory Traversal Attempt Detected on Windows Endpoint'

```

### 3. Analyze Defense Execution Results on Wazuh Dashboard

Access **Wazuh Dashboard** central monitoring (`Threat Hunting` → `Events`), System simultaneously triggers two types of valuable alerts:

* **Attack detection alert (Rule 100002):** Bursts orange level 10 alert clearly warning unauthorized directory traversal behavior targeting Windows Endpoint. When checking detailed `Document Details` field, two values `data.srcip: 192.168.71.130` and mutated payload `data.url` are clearly displayed, proving Custom Decoder's parsing capability.
![Alert result of behavior on Dashboard](images/phase3/scenario2/dashboard.png)
![Alert details](images/phase3/scenario2/alert-detail.png)


* **Proactive defense alert (Rule 657):** System records event triggering blocking command `netsh.exe - add` successfully.
Check local `active-responses.log` log file at `C:\Program Files (x86)\ossec-agent\active-responses.log` path of Windows machine, firewall execution command line is recorded in real time:
```text
active-response/bin/netsh.exe add - 192.168.71.130
```
![Active Response on Dashboard](images/phase3/scenario2/active-response.png)

Meanwhile, when checking *Inbound Rules* table in victim's Windows Defender Firewall interface, an emergency rule named **`WAZUH ACTIVE RESPONSE BLOCKED IP`** is automatically generated, firmly pinning Kali machine's IP (`192.168.71.130`) to blocked connection list.
![Block attacker machine IP](images/phase3/scenario2/block-attacker-check.png)

Final proof, when standing from Kali machine performing sending third attack or reconnaissance request to Web Server, entire packet is completely blocked right from network border layer, `curl` command falls into frozen state:
![Block Kali machine](images/phase3/scenario2/block-attacker.png)

---

## V. Summary of Scenario 2

Scenario simulates web application attack via Local File Inclusion (LFI) vulnerability and activates Active Response defense mechanism ending in great success. Thereby proving mastery of complex character string decoding technology, setting up intelligent analysis rules overriding system (`overwrite="yes"`) handling well evasion filter variants.

Especially, closed security cycle from Detect → Alert → Auto-isolate threat at network border has affirmed real-world power of modern enterprise SOC system, absolutely protecting application infrastructure from outward-facing application exploitation techniques (`T1190`).

## References

* [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)
