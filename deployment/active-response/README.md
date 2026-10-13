# 🛑 Endpoint Active Response Scripts

Thư mục chứa các kịch bản thực thi phản ứng tức thì được kích hoạt bởi **Wazuh Active Response Engine** trên máy trạm Windows 10 Endpoint.

---

## 📌 Danh Mục Kịch Bản

| Kịch Bản | Mục Tiêu Phản Ứng | Cơ Chế An Toàn (Safety Guard) |
| :--- | :--- | :--- |
| `kill-process.ps1`<br/>`kill-process.cmd` | Tiêu diệt tiến trình độc hại tức thì (`Stop-Process -Force`) khi phát hiện PowerShell mã hóa (Rule 100004) hoặc LSASS Memory Dump (Rule 100005). | **Safe Whitelist:** Tuyệt đối không kill các tiến trình hệ thống trọng yếu (`csrss.exe`, `lsass.exe`, `winlogon.exe`, `services.exe`, `wazuh-agent.exe`) để ngăn chặn BSOD. |
| `collect-evidence.ps1`<br/>`collect-evidence.cmd` | Thu thập dữ liệu pháp y số (Forensic Triage): RAM mini-dump, kết nối mạng `netstat -ano`, active sessions, và log EVTX trước khi triệt tiêu mối đe dọa. | Tự động đặt timeout, nén file `.zip` và không làm gián đoạn hiệu năng hệ thống. |

---

## 🛠️ Vị Trí Cài Đặt Trên Windows Endpoint
Toàn bộ các file `.cmd` và `.ps1` được sao chép vào thư mục Active Response của Wazuh Agent:
```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```
Được khai báo trong `<active-response>` block trên file cấu hình `ossec.conf`.
