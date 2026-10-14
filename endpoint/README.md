# 💻 Wazuh Endpoint Provisioning Package (Windows 10)

Thư mục đóng gói toàn diện các cấu hình, module bảo mật và kịch bản thiết lập cho máy trạm **Windows 10 Target (`192.168.71.129`)**.

---

## ⚡ HƯỚNG DẪN TRIỂN KHAI 2 BƯỚC (QUICKSTART)

### Bước 1: Cài đặt phần mềm nền tảng (Người dùng cài trước)
Nếu máy Windows 10 mới hoàn toàn chưa có phần mềm, bạn tải và cài đặt 2 công cụ chính hãng sau:

1. **Cài đặt Wazuh Agent 4.14.5 (Chính hãng):**
   * Tải bộ cài MSI: [wazuh-agent-4.14.5-1.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi)
   * Chạy CMD (Run as Admin) và thực thi lệnh cài đặt:
     ```cmd
     msiexec.exe /i wazuh-agent-4.14.5-1.msi /q WAZUH_MANAGER="192.168.71.128" WAZUH_REGISTRATION_SERVER="192.168.71.128"
     ```

2. **Cài đặt Microsoft Sysmon v15.2 (Sysinternals):**
   * Tải tệp zip: [Microsoft Sysinternals Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip)
   * Giải nén file zip vào một thư mục (ví dụ `C:\Sysmon` hoặc để file `Sysmon64.exe` trong biến môi trường PATH).
   * Chạy cài đặt ban đầu:
     ```cmd
     Sysmon64.exe -accepteula -i
     ```

---

### Bước 2: Chạy Script Tự Động Của Lab (1-Click Master Setup)
Mở cửa sổ **PowerShell với quyền Administrator** trong thư mục này và gõ:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_endpoint.ps1 -WazuhManagerIP "192.168.71.128"
```

**Script `setup_endpoint.ps1` sẽ tự động thực hiện 100% các công việc còn lại:**
1. ✅ Nạp cấu hình lọc sự kiện Sysmon tối ưu theo MITRE ATT&CK (`config\sysmon-config.xml`).
2. ✅ Nạp cấu hình Agent `ossec.conf` (bật FIM realtime cho `C:\Users\Public`, giám sát Sysmon Eventchannel và Apache log).
3. ✅ Đăng ký các kịch bản Active Response (`kill-process.ps1`, `collect-evidence.ps1`) vào `C:\Program Files (x86)\ossec-agent\active-response\bin\`.
4. ✅ Kích hoạt Windows Object Access Auditing (SACL Event 4663).
5. ✅ Khởi tạo hệ sinh thái bẫy mồi Deception (Canary File `IT_Admin_Credentials.xlsx` và Honey-Account `backup_admin`).
6. ✅ Cấu hình kênh quản trị an toàn WinRM (Port 5985) phục vụ phản ứng khép kín SOAR.
7. ✅ Khởi động lại dịch vụ Wazuh Agent.

---

## 🗂️ Cấu Trúc Thư Mục `endpoint/`

```text
endpoint/
├── README.md                      # Hướng dẫn triển khai máy trạm Windows 10
├── setup_endpoint.ps1             # Script master 1-Click tự động hóa toàn bộ cấu hình
├── config/
│   ├── ossec.conf                 # Cấu hình chuẩn của Wazuh Agent (FIM, Channels, AR)
│   └── sysmon-config.xml          # Cấu hình Sysmon v15.2 tối ưu theo MITRE ATT&CK
├── active-response/               # Kịch bản phản ứng tức thì trên Endpoint
│   ├── kill-process.cmd / .ps1    # Diệt tiến trình độc hại (Safe Whitelist chống BSOD)
│   └── collect-evidence.cmd / .ps1# Tự động nén RAM dump + netstat + EVTX thành .zip
└── deception/                     # Mạng lưới bẫy mồi chủ động (0% False Positive)
    ├── setup_canary.ps1           # Tạo file Canary SACL & tài khoản mồi backup_admin
    ├── network_decoy.py           # Listener giả lập dịch vụ FTP Port 21
    └── collect_evidence.ps1       # Script trích xuất chứng cứ pháp y số trực tiếp
```
