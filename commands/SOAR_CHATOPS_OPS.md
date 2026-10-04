# 🤖 Cẩm Nang Vận Hành SOAR n8n, ChatOps Telegram & Jira Cloud

Tài liệu hướng dẫn điều phối, bảo trì, giám sát log và khắc phục sự cố hệ thống tự động hóa phản ứng an ninh mạng (SOAR Engine).

---

## 📌 Các Cổng Dịch Vụ & Địa Chỉ Truy Cập

| Dịch Vụ | Địa Chỉ URL / Port | Thông Tin Đăng Nhập / Ghi Chú |
| :--- | :--- | :--- |
| **n8n Web Editor** | `http://192.168.71.128:5678` | Trực quan hóa và debug canvas 3 workflows |
| **Wazuh Dashboard** | `https://192.168.71.128:443` | `admin` / `SecretPassword123!` |
| **Telegram Bot** | `https://t.me/my_wazuh_soc_alert_bot` | `@my_wazuh_soc_alert_bot` |
| **Jira Cloud Board** | `https://tn421015.atlassian.net` | Project Key: `KAN` |

---

## 1. ⚙️ Quản Lý Container n8n SOAR Engine (`wazuh-vm`)

### Xem trạng thái container n8n:
```powershell
ssh wazuh-vm "docker ps --filter name=n8n-soar-engine --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
```

### Xem log trực tiếp của n8n (Realtime Debugging):
```powershell
# Xem 50 dòng log mới nhất:
ssh wazuh-vm "docker logs --tail 50 n8n-soar-engine"

# Theo dõi log thời gian thực (Follow):
ssh wazuh-vm "docker logs -f --tail 20 n8n-soar-engine"
# (Bấm Ctrl+C để thoát)
```

### Khởi động lại hoặc dừng cụm n8n:
```powershell
# Khởi động lại:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose restart"

# Nạp lại cấu hình từ file .env mới:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose up -d"

# Dừng container:
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose down"
```

---

## 2. 📡 Quản Lý Cầu Nối Callback Telegram (`telegram_bridge.py`)

Do máy chủ Lab ở trong dải mạng nội bộ không có IP Public, tiến trình Python `telegram_bridge.py` sử dụng kỹ thuật **Telegram Long-Polling** để đón các sự kiện bấm nút tương tác từ Telegram và chuyển tiếp vào webhook của n8n.

### Kiểm tra tiến trình đang chạy:
```powershell
ssh wazuh-vm "ps aux | grep telegram_bridge | grep -v grep"
```

### Xem log tiếp nhận nút bấm Callback:
```powershell
ssh wazuh-vm "tail -n 25 /home/nguyentoan/n8n-docker/telegram_bridge.log"
```
*Log mẫu ghi nhận thành công:*
```text
2026-10-04 21:38:43,497 [INFO] Starting Telegram -> n8n ChatOps Callback Bridge...
2026-10-04 21:38:43,499 [INFO] Target n8n Webhook: http://127.0.0.1:5678/webhook/telegram-callback
2026-10-04 21:40:02,120 [INFO] Received Callback Query from @Khánh Toàn: action:jira:100005:192.168.71.129:1791103745
2026-10-04 21:40:02,185 [INFO] Forwarded callback 456583364 to n8n -> HTTP 200
```

### Khởi động lại thủ công tiến trình Telegram Bridge:
```powershell
ssh wazuh-vm "/home/nguyentoan/n8n-docker/restart_bridge.sh"
```

---

## 3. 🛡️ Kiểm Tra & Thu Hồi Luật Tường Lửa (Containment Verification)

Khi Analyst bấm nút **`[🚫 Khóa IP 24h]`** trên Telegram:

### Kiểm tra các luật chặn đã tạo trên Windows 10:
```powershell
$cred = Get-Credential -UserName socrunner
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" -or $_.DisplayName -like "*SOAR*" } | Select-Object Name, DisplayName, Direction, Action, Enabled
}
```

### Xóa bỏ (Thu hồi) lệnh cách ly để mở lại kết nối cho máy thử nghiệm:
```powershell
Invoke-Command -ComputerName 192.168.71.129 -Credential $cred -ScriptBlock {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*WAZUH*" -or $_.DisplayName -like "*SOAR*" } | Remove-NetFirewallRule
    Write-Host "✅ Đã gỡ bỏ toàn bộ luật chặn firewall thử nghiệm."
}
```

---

## 4. 🎫 Kiểm Tra Tích Hợp Jira Cloud REST API

### Kiểm tra tính hợp lệ của Token Atlassian từ máy Host:
```powershell
# Chạy script test đồng bộ để xác thực tức thì:
python -c "
import urllib.request, base64, os
from dotenv import load_dotenv
load_dotenv()
domain = os.getenv('JIRA_DOMAIN', '').replace('https://', '').strip('/')
auth = base64.b64encode(f\"{os.getenv('JIRA_EMAIL')}:{os.getenv('JIRA_API_TOKEN')}\".encode()).decode()
req = urllib.request.Request(f'https://{domain}/rest/api/3/myself', headers={'Authorization': f'Basic {auth}', 'Accept': 'application/json'})
with urllib.request.urlopen(req) as resp:
    print('✅ Jira Status:', resp.status, 'User OK')
"
```

### Xem trực tiếp danh sách Ticket vừa tạo trên Jira Web:
Truy cập trình duyệt: `https://tn421015.atlassian.net/jira/software/projects/KAN/boards/2`
Hoặc truy vấn ticket cụ thể: `https://tn421015.atlassian.net/browse/KAN-15`
