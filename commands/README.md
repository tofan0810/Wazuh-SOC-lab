# 🧭 Trung Tâm Cẩm Nang Lệnh (Command Central Hub)

Thư mục `commands/` chứa toàn bộ cẩm nang lệnh thực thi từ xa, kích hoạt tấn công, kiểm thử tự động và vận hành hệ thống phòng Lab Wazuh SOC.

---

## 📚 Danh Mục Cẩm Nang Hướng Dẫn

| Tài Liệu Hướng Dẫn | Mục Đích & Nội Dung Chính | Đường Dẫn Nhanh |
| :--- | :--- | :--- |
| **1. Cẩm Nang Thực Thi Từ Xa** | Hướng dẫn gọi lệnh SSH/WinRM từ PowerShell máy Host vào 3 máy ảo (Kali, Wazuh, Windows) mà không cần chuyển màn hình VMware. | [`REMOTE_EXECUTION.md`](REMOTE_EXECUTION.md) |
| **2. Cẩm Nang Kích Hoạt Tấn Công & E2E** | Hướng dẫn chạy 3 kịch bản tấn công (RDP, LFI, Full Kill Chain), bộ test tự động Python Runners và kiểm tra luật Wazuh. | [`ATTACK_AND_TEST_GUIDE.md`](ATTACK_AND_TEST_GUIDE.md) |
| **3. Cẩm Nang Vận Hành SOAR & ChatOps** | Hướng dẫn quản lý n8n Docker, daemon Telegram Bridge, gỡ luật chặn Firewall và kiểm tra tích hợp Jira Cloud. | [`SOAR_CHATOPS_OPS.md`](SOAR_CHATOPS_OPS.md) |
| **4. Cẩm Nang Đồng Bộ Cấu Hình (.env)** | Hướng dẫn sử dụng công cụ tự động `sync_env.bat` / `sync_env.py` để cập nhật API Key, Token và cấu hình toàn hệ thống. | [`CONFIG_SYNC_COMMANDS.md`](CONFIG_SYNC_COMMANDS.md) |

---

## 📌 Bảng Tra Cứu Nhanh Hạ Tầng & Dịch Vụ Lab

| Máy Ảo / Dịch Vụ | IP / Cổng Kết Nối | Giao Thức / Tài Khoản | Mục Đích |
| :--- | :--- | :--- | :--- |
| **Kali Linux** | `192.168.71.130` (Port 22) | SSH (User: `kali`) | Máy tấn công giả lập (Attacker) |
| **Ubuntu Wazuh** | `192.168.71.128` (Port 22) | SSH (User: `nguyentoan`) | Máy chủ SIEM & SOAR Engine |
| **Windows 10** | `192.168.71.129` (Port 5985) | WinRM (User: `socrunner`) | Máy trạm nạn nhân (Endpoint) |
| **Wazuh Dashboard** | `https://192.168.71.128:443` | Web UI (`admin`) | Giám sát SIEM, Alerts, Dashboards |
| **n8n SOAR Editor** | `http://192.168.71.128:5678` | Web UI | Thiết kế và giám sát Workflows SOAR |
| **Telegram Bot** | `@my_wazuh_soc_alert_bot` | HTTPS (Chat ID: `8696241190`) | Kênh ChatOps thông báo & duyệt phản ứng |
| **Jira Cloud** | `https://tn421015.atlassian.net` | REST API v3 (Project: `KAN`) | Hệ thống quản lý vé sự cố (Case Mgmt) |

---

## ⚡ Các Lệnh Thực Hiện Thường Dùng Nhất (Cheatsheet Nhanh)

```powershell
# 1. Kiểm tra sức khỏe toàn bộ phòng Lab:
python tests/e2e/lab_health.py

# 2. Đồng bộ hóa cấu hình sau khi sửa .env (1-Click):
.\sync_env.bat

# 3. Kích hoạt tấn công & kiểm thử Scenario 3 (Full Kill Chain):
python tests/e2e/scenario_full_killchain.py --execute

# 4. Kiểm tra cảnh báo thời gian thực trên Wazuh Manager:
ssh wazuh-vm "sudo tail -f /var/ossec/logs/alerts/alerts.json"

# 5. Xem log tiếp nhận phản ứng nút bấm Telegram ChatOps:
ssh wazuh-vm "tail -f /home/nguyentoan/n8n-docker/telegram_bridge.log"
```
