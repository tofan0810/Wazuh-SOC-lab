# 🍯 Deception Technology & Digital Forensics (Phase 10)

Thư mục lưu trữ các kịch bản triển khai công nghệ bẫy mồi chủ động (**Active Defense / Deception Grid**) và module tự động thu thập chứng cứ pháp y số (**Live Forensics Preservation**).

---

## 📌 Danh Mục Thành Phần

| Tệp Tin | Loại Bẫy / Chức Năng | Cơ Chế Kích Hoạt | Wazuh Rule & Phản Ứng |
| :--- | :--- | :--- | :--- |
| `setup_canary.ps1` | **Canary Honey-File & Honey-Account** | Tạo file `C:\Users\Public\IT_Admin_Credentials.xlsx` kèm SACL Audit quyền Read; tạo tài khoản mồi `backup_admin`. | **Rule 100014** (Canary File read - Event 4663)<br/>**Rule 100015** (Honey-Account logon - Event 4625)<br/>*Tỷ lệ cảnh báo giả 0% (Zero FP)*. |
| `network_decoy.py`<br/>`network_decoy.ps1` | **Network Service Decoy (FTP 21)** | Socket listener mở cổng TCP 21, phản hồi banner `220 Microsoft FTP Service`, ghi nhận hành vi dò quét dịch vụ (T1046). | **Rule 100016** (FTP Decoy Touch)<br/>Khóa IP kẻ tấn công tức thì. |
| `collect_evidence.ps1` | **Automated DFIR Triage** | Tự động trích xuất RAM mini-dump của tiến trình vi phạm, bảng kết nối mạng, active sessions và security EVTX nén thành `Evidence_<AlertId>.zip`. | Tự động đính kèm lên **Jira Cloud Incident Ticket**. |

---

## ⚡ Lệnh Triển Khai Trên Windows Endpoint
```powershell
# 1. Kích hoạt bẫy mồi Canary File & Honey-Account
powershell -ExecutionPolicy Bypass -File deployment\deception\setup_canary.ps1

# 2. Khởi chạy Network Decoy (FTP Port 21)
python deployment\deception\network_decoy.py
```
