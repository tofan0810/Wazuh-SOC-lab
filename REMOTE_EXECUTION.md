# 🚀 Hướng Dẫn Gọi Lệnh Từ Xa (Remote Execution Cheat-Sheet)

Tài liệu hướng dẫn gọi lệnh trực tiếp từ **PowerShell trên máy Windows Host (thật)** vào **3 máy ảo VMware** mà không cần chuyển màn hình.

---

## 📌 Thông Tin Mạng & Tài Khoản Lab

| Máy Ảo | Địa Chỉ IP | Giao Thức | Tài Khoản / Alias SSH |
| :--- | :--- | :--- | :--- |
| **Kali Linux** (Attacker) | `192.168.71.130` | SSH (Port 22) | Host: `kali-vm` (User: `kali`) |
| **Ubuntu Wazuh** (Manager) | `192.168.71.128` | SSH (Port 22) | Host: `wazuh-vm` (User: `nguyentoan`) |
| **Windows 10** (Victim) | `192.168.71.129` | WinRM (Port 5985) | User: `socrunner` |

---

## 1. ⚔️ Máy KALI LINUX (Attacker)

### Chạy 1 lệnh nhanh từ Host:
```powershell
# Xem IP và người dùng:
ssh kali-vm "hostname; whoami; ip -br a"

# Kiểm tra tiến trình tấn công (xfreerdp / curl):
ssh kali-vm "ps aux | grep -E 'xfreerdp|curl'"
```

### Mở Terminal tương tác (nhảy vào máy Kali):
```powershell
ssh kali-vm
# Thoát ra: gõ 'exit'
```

---

## 2. 🛡️ Máy UBUNTU WAZUH MANAGER (SIEM)

### Chạy 1 lệnh nhanh từ Host:
```powershell
# Xem trạng thái cụm 3 Docker container (Manager, Indexer, Dashboard):
ssh wazuh-vm "cd ~/wazuh-docker/single-node && docker compose ps"

# Kiểm tra tài nguyên RAM / CPU máy chủ Wazuh:
ssh wazuh-vm "free -m; docker stats --no-stream"

# Xem 10 cảnh báo Alert Wazuh mới nhất sinh ra:
ssh wazuh-vm "sudo tail -n 10 /var/ossec/logs/alerts/alerts.json"

# Khởi động lại dịch vụ wazuh bên trong container Manager:
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart"
```

### Mở Terminal tương tác:
```powershell
ssh wazuh-vm
# Thoát ra: gõ 'exit'
```

---

## 3. 🎯 Máy WINDOWS 10 VICTIM (Target Endpoint)

*Trên PowerShell máy Host, lưu mật khẩu vào biến tạm 1 lần duy nhất trong phiên làm việc:*
```powershell
$cred = Get-Credential -UserName socrunner
```

### Cách A: Chạy 1 lệnh hoặc khối lệnh nhanh (`Invoke-Command`)
```powershell
# 1. Kiểm tra trạng thái dịch vụ Wazuh Agent:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-Service WazuhSvc
}

# 2. Kiểm tra port 80 Apache (XAMPP):
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    netstat -ano | Select-String ":80\s+.*LISTENING"
}

# 3. Xem danh sách Rule Firewall do Wazuh Active Response tự động tạo:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
}

# 4. Xem 10 dòng log Active Response mới nhất:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 10
}

# 5. Khởi động lại dịch vụ Wazuh Agent:
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Restart-Service WazuhSvc
}
```

### Cách B: Mở Shell tương tác vào hẳn máy Windows 10 (`Enter-PSSession`)
```powershell
Enter-PSSession -ComputerName 192.168.71.129 -Credential $cred
```
*Dấu nhắc lệnh chuyển thành `[192.168.71.129]: PS C:\...>` — Thao tác trực tiếp trên máy ảo. Gõ `exit` để thoát.*

---

## 4. ⚡ Lệnh Kiểm Tra Nhanh Cả 3 Máy Cùng Lúc (Health 1-Liner)

Chạy dòng lệnh này trên PowerShell máy Host để kiểm tra kết nối cả 3 máy:
```powershell
Write-Host "--- KALI ---"; ssh -o BatchMode=yes kali-vm "hostname; whoami"; Write-Host "--- WAZUH ---"; ssh -o BatchMode=yes wazuh-vm "hostname; docker ps --format '{{.Names}}: {{.Status}}'"; Write-Host "--- WINDOWS 10 ---"; Test-WSMan 192.168.71.129
```
Hoặc dùng script có sẵn của lab:
```powershell
python tests/e2e/lab_health.py
```
