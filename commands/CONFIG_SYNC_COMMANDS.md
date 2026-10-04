# 🔄 Cẩm Nang Đồng Bộ Cấu Hình & Biến Môi Trường (.env)

Tài liệu hướng dẫn quy trình cập nhật và đồng bộ cấu hình từ file `.env` lên toàn bộ hệ thống Wazuh SIEM, n8n SOAR, Telegram Bridge và Jira Cloud.

---

## 🚀 Cách 1: Sử Dụng Công Cụ Tự Động Hóa 1-Click (Khuyên Dùng)

Bất cứ khi nào bạn chỉnh sửa file `.env` (thay đổi Token Telegram, Chat ID, Jira Token, API Key VirusTotal / AbuseIPDB, hoặc đổi IP máy ảo):

### 1. Nhấp đúp chuột (Double-Click):
Chỉ cần nhấp đúp vào file [`sync_env.bat`](../../sync_env.bat) nằm ngay tại thư mục gốc của dự án.

### 2. Hoặc chạy từ Terminal (PowerShell / CMD):
```powershell
# Chạy script Python điều phối:
python scripts/sync_env.py

# Hoặc chạy file batch:
.\sync_env.bat
```

---

## ⚙️ Các Thao Tác Script Sẽ Tự Động Thực Hiện

1. **Kiểm tra hợp lệ API Keys (Pre-flight Validation):**
   - Gửi yêu cầu kiểm tra tới Telegram API (`/getMe`).
   - Gửi xác thực Basic Auth tới Jira Cloud API (`/rest/api/3/myself`).
   - Kiểm tra hạn ngạch AbuseIPDB (`/api/v2/check`).
2. **Cập nhật cấu hình cục bộ:**
   - Cập nhật các khối `<integration>` trong [`deployment/ossec.conf`](../../deployment/ossec.conf).
   - Cập nhật các template Workflow trong [`integrations/n8n/workflows/`](../../integrations/n8n/workflows/).
3. **Đẩy sang máy chủ Wazuh qua SSH/SCP:**
   - Đẩy `.env` sang `/home/nguyentoan/n8n-docker/.env`.
   - Nạp `ossec.conf` mới vào container `single-node-wazuh.manager-1`.
   - Đồng bộ các file workflow JSON sang thư mục Docker của n8n.
4. **Tái khởi động và áp dụng dịch vụ:**
   - Tự động gọi `/var/ossec/bin/wazuh-control restart`.
   - Tự động cập nhật container `n8n-soar-engine` (`docker compose up -d`).
   - Tự động khởi động lại daemon ngầm `telegram_bridge.py`.
5. **In bảng báo cáo sức khỏe (Health Check Report) trực quan.**

---

## 🛠️ Cách 2: Quy Trình Cập Nhật Thủ Công Từng Bước (Manual Fallback)

Nếu trong trường hợp không có Python hoặc cần thao tác thủ công từng thành phần:

### Bước 1: Sao chép file `.env` sang `wazuh-vm`
```powershell
scp .env wazuh-vm:/home/nguyentoan/n8n-docker/.env
```

### Bước 2: Nạp cấu hình vào Wazuh Manager Container
```powershell
scp deployment/ossec.conf wazuh-vm:/tmp/ossec.conf
ssh wazuh-vm "docker cp /tmp/ossec.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf"
ssh wazuh-vm "docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart"
```

### Bước 3: Khởi động lại n8n Container
```powershell
ssh wazuh-vm "cd /home/nguyentoan/n8n-docker && docker compose up -d"
```

### Bước 4: Khởi động lại daemon Telegram Bridge
```powershell
ssh wazuh-vm "/home/nguyentoan/n8n-docker/restart_bridge.sh"
```

---

## 🔍 Khắc Phục Sự Cố Thường Gặp (Troubleshooting)

### 1. Báo lỗi `Không thể kết nối SSH tới wazuh-vm`:
- Kiểm tra máy ảo Ubuntu Wazuh đã khởi động trên VMware chưa.
- Kiểm tra cấu hình SSH alias trong `C:\Users\<User>\.ssh\config`:
  ```text
  Host wazuh-vm
      HostName 192.168.71.128
      User nguyentoan
  ```

### 2. Telegram Bot không phản hồi nút bấm Callback:
- Kiểm tra log của daemon bridge:
  ```powershell
  ssh wazuh-vm "tail -n 20 /home/nguyentoan/n8n-docker/telegram_bridge.log"
  ```
- Nếu thấy thông báo `Unauthorized` $\rightarrow$ Token bot trong `.env` chưa đúng, hãy cập nhật lại và chạy `.\sync_env.bat`.
