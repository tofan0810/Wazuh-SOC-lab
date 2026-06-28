# Wazuh SIEM & Detection Engineering Lab

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)](https://attack.mitre.org/)

> 🌐 Switch to the [feature/english-version](https://github.com/tofan0810/Wazuh-SOC-lab/tree/feature/english-version) branch to view this documentation in English.

## 📝 Tổng quan Đồ án

Kho lưu trữ này chứa sơ đồ kiến trúc, các file cấu hình và chi tiết triển khai của **Hệ thống Giám sát An ninh mạng & Ứng phó Sự cố Tập trung** được xây dựng trên nền tảng **Wazuh SIEM/XDR**. Được thiết kế nhằm giả lập môi trường vận hành thực tế của một doanh nghiệp, đồ án này tập trung sâu vào việc thu thập log, tự viết luật phát hiện tấn công (**Detection Engineering**) chuẩn hóa theo framework **MITRE ATT&CK**, tự động hóa phòng thủ (**Active Response**) và kích hoạt cảnh báo theo thời gian thực.

### Mục tiêu Cốt lõi:
*   Triển khai hạ tầng SIEM/XDR hoạt động ổn định sử dụng mã nguồn mở.
*   Cấu hình kiểm toán chuyên sâu trên máy trạm (Endpoint Auditing) thông qua **Windows Sysmon** và log hệ thống.
*   Xây dựng **Custom Decoders và Rules (Luật tự viết)** để phát hiện các kỹ thuật tấn công tinh vi.
*   Triển khai cơ chế phòng thủ chủ động **Active Response** để tự động ngăn chặn các mối đe dọa đang diễn ra.
*   Tích hợp hệ thống cảnh báo thời gian thực về kênh giám sát tập trung (Telegram/Discord) **(Sẽ được nghiên cứu và phát triển trong tương lai)**.

---

## 🏗️ Kiến trúc & Thiết lập Lab

### Mô hình Topology và Luồng dữ liệu
```text
                   ┌─────────────────────┐
                   │ Kali Linux          │
                   │ Attacker            │  
                   │ (IP: 192.168.71.130)│
                   └───────┬─────────────┘
                           │
                           │ Tấn công
                           ▼
                   ┌──────────────────────┐
                   │ Windows 10           │
                   │ Wazuh Agent          │
                   │ (IP: 192.168.71.129) │
                   └───────┬──────────────┘
                           │
                           │ Logs (Sysmon/Security/Apache)
                           ▼
                   ┌────────────────────────────────┐
                   │ Ubuntu Server (Wazuh Manager)  │
                   │ Docker Single-Node             │
                   │ (IP: 192.168.71.128)           │
                   │ Wazuh Indexer (Lưu trữ log)    │
                   │ Wazuh Dashboard (Giao diện)    │
                   └───────┬────────────────────────┘
                           │
                           │ Alerts
                           ▼
                   ┌─────────────────┐
                   │ Wazuh           │
                   │ Dashboard       │
                   └─────────────────┘
```

> 💡 **Lưu ý chi tiết các bước triển khai được ghi lại trong các báo cáo tại thư mục `reports/`.

### Thông số kỹ thuật các thành phần:
1. **Wazuh Manager (Chạy trên Ubuntu Server 22.04/24.04):
   - Đóng vai trò trung tâm chịu trách nhiệm biên dịch log (decode), đối khớp rule, kích hoạt alert và phát lệnh ứng phó tự động.
   - Triển khai qua Docker Compose (Single-Node Architecture).
   - Đã cấu hình thay đổi mật khẩu quản trị, giới hạn log container, kernel hardening (vm.max_map_count=262144).
2. **Giám sát Endpoint (Máy Windows 10 Pro):
   - Được cài đặt **Wazuh Agent 4.14.5** phối hợp cùng **Microsoft Sysmon v15.2** (sử dụng file cấu hình tùy chỉnh) nhằm bắt trọn các hành vi ở tầng nhân (kernel) và tiến trình hệ thống.
   - Đã cấu hình log_alert_level=0 để thu thập toàn bộ log.
3. **Nền tảng Tấn công (Máy Kali Linux):
   - Sử dụng để giả lập các kỹ thuật tấn công của tin tặc hướng vào máy Windows 10 nhằm sinh log kiểm thử.

---

## 🗂️ Cấu trúc Thư mục Repo

```text
wazuh-soc-lab/
│
├── README.md               # Tài liệu chính
├── documents/              # Tài liệu lý thuyết và lệnh thường dùng
│
├── architecture/           # Chứa ảnh sơ đồ mạng (mô hình topology)
│
├── deployment/             # Hướng dẫn hoặc script cài đặt
│   ├── docker-compose.yml  # File cấu hình Docker Compose để triển khai Wazuh bằng Docker Compose
│   └── sysmon-config.xml   # File cấu hình Sysmon tối ưu
│
├── custom-rules/           # Chứa các rule XML do tôi tự viết
│   ├── local_rules.xml
│   └── local_decoder.xml
│
├── integrations/           # Code tích hợp gửi alert **(Sẽ được phát triển trong tương lai)**
│
└── reports/                # File báo cáo chi tiết các giai đoạn triển khai
    ├── Phase-1_Infrastructure-Deployment.md
    ├── Phase-2_Agent-Sysmon-Configuration.md
    ├── Phase-3_Scenario-1.md
    ├── Phase-3_Scenario-2.md
    └── images/
```

---

## 🚀 Kịch bản Tấn công & Phát hiện Thực chiến (Đã triển khai thành công)

### 🔹 Kịch bản 1: T1110 - PHÁT HIỆN TẤN CÔNG BRUTE FORCE RDP & TỰ ĐỘNG KHÓA IP (ACTIVE RESPONSE)
* **Mô hình tấn công:** Sử dụng `xfreerdp` từ máy Kali Linux để thực hiện quét dò mật khẩu tốc độ cao qua giao thức RDP.
* **Thu thập Telemetry (Log):** Theo dõi log đăng nhập hệ thống Windows Event ID 4625 (Đăng nhập thất bại).
* **Chiến lược phát hiện:** Custom Rule ID 100001 (Level 12) phát hiện nhiều lần đăng nhập thất bại liên tiếp.
* **Phản ứng giảm thiểu (Active Response):** Tự động gọi lệnh `netsh` trên Windows Agent để block IP attacker trong 600 giây (10 phút).
* **Minh chứng thực tế (PoC):** Xem chi tiết tại `reports/Phase-3_Scenario-1.md`.


### 🔹 Kịch bản 2: T1190 - KHAI THÁC LỖ HỔNG ỨNG DỤNG WEB (LOCAL FILE INCLUSION - LFI / DIRECTORY TRAVERSAL)
* **Mô hình tấn công:** Sử dụng `curl` từ Kali để khai thác lỗ hổng LFI trên ứng dụng XAMPP Apache, cố gắng đọc file `win.ini`.
* **Thu thập Telemetry (Log):** Cấu hình Wazuh Agent thu thập Apache Access Log.
* **Chiến lược phát hiện:** Custom Decoder bóc tách URL + Custom Rule ID 100002 (Level 10) phát hiện các chuỗi ký tự độc hại (`..%2f`, `..%252f`, `win.ini`, `boot.ini`).
* **Phản ứng giảm thiểu (Active Response):** Tự động block IP attacker trong 600 giây.
* **Minh chứng thực tế (PoC):** Xem chi tiết tại `reports/Phase-3_Scenario-2.md`.


---

## 🤖 Tích hợp SOAR: Hệ thống Cảnh báo qua Kênh Chat (ChatOps)
> ⚠️ **Ghi chú:** Tính năng này **sẽ được nghiên cứu và phát triển trong tương lai. Hiện tại, hệ thống đã hoàn thành 2 kịch bản tấn công và phát hiện cùng cơ chế Active Response.

---

## 🛠️ Hướng dẫn Cài đặt & Triển khai
Xem chi tiết các bước tại các báo cáo trong thư mục `reports/`:
1. Triển khai hạ tầng Wazuh Stack: `reports/Phase-1_Infrastructure-Deployment.md`
2. Cấu hình Agent và Sysmon: `reports/Phase-2_Agent-Sysmon-Configuration.md`
3. Triển khai kịch bản tấn công và phát hiện: `reports/Phase-3_Scenario-1.md` và `reports/Phase-3_Scenario-2.md`

### Điều kiện tiên quyết:
*   Phần mềm máy ảo: VMware Workstation hoặc VirtualBox.
*   Tài nguyên phần cứng khuyến nghị:
  - Ubuntu Server: Ít nhất 2 vCPU, 4GB RAM, 65GB SSD.
  - Windows 10: Ít nhất 2 vCPU, 2GB RAM.


---

## 📊 Kỹ năng Thực tế Đạt được qua Đồ án này
*   **Quản trị và Vận hành SIEM/XDR:** Nắm vững kiến trúc hệ thống, cài đặt phân hệ Agent, tối ưu hóa nguồn log nạp vào.
*   **Kỹ nghệ Phát hiện Tấn công (Detection Engineering):** Thành thạo kỹ năng viết luật bằng cấu trúc XML, thiết kế bộ lọc decoder, sử dụng biểu thức chính quy (Regex) và tư duy tối ưu giảm thiểu cảnh báo giả (False-Positive).
*   **Phân tích Telemetry Máy trạm (Endpoint):** Hiểu sâu sắc cơ chế ghi log hệ thống Windows Event Logs, cấu trúc bảng dữ liệu của Sysmon nâng cao.
*   **Tự động hóa & Ứng phó Sự cố:** Kích hoạt kịch bản cô lập chủ động thông qua Active Response và cấu hình luồng dữ liệu tự động hóa thông báo (Webhook Notification Flows).

---

## 📚 Tài liệu tham khảo
- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
