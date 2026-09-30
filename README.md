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
*   Tích hợp hệ thống cảnh báo thời gian thực về kênh giám sát tập trung qua **Telegram ChatOps**.
*   Tự động hóa đối soát mối đe dọa với nền tảng **Threat Intelligence (VirusTotal API)**.
*   Xây dựng bộ quy trình chuẩn ứng phó sự cố (**Incident Response Playbooks / SOP**) theo tiêu chuẩn **NIST SP 800-61** và **SANS PICERL**.

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
                           │ Tấn công (RDP Brute Force, Web LFI)
                           ▼
                   ┌──────────────────────┐
                   │ Windows 10           │
                   │ Wazuh Agent + Sysmon │
                   │ (IP: 192.168.71.129) │
                   └───────┬──────────────┘
                           │
                           │ Telemetry (Sysmon / Security / Apache / FIM)
                           ▼
                   ┌────────────────────────────────┐
                   │ Ubuntu Server (Wazuh Manager)  │
                   │ Docker Single-Node             │
                   │ (IP: 192.168.71.128)           │
                   │ • Wazuh Analysis Engine        │
                   │ • Active Response Engine       │
                   │ • Integrator Daemon            │
                   └───────┬────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │    Wazuh    │  │ VirusTotal  │  │  Telegram   │
   │  Dashboard  │  │ Threat Intel│  │   ChatOps   │
   │ (Index/Logs)│  │ (Cloud API) │  │ (Real-time) │
   └─────────────┘  └─────────────┘  └─────────────┘
```

> 💡 **Lưu ý:** Chi tiết các bước triển khai được ghi lại trong các báo cáo tại thư mục `reports/`.

### Thông số kỹ thuật các thành phần:
1. **Wazuh Manager (Chạy trên Ubuntu Server 22.04/24.04):**
   - Đóng vai trò trung tâm chịu trách nhiệm biên dịch log (decode), đối khớp rule, kích hoạt alert và phát lệnh ứng phó tự động.
   - Triển khai qua Docker Compose (Single-Node Architecture).
   - Đã cấu hình thay đổi mật khẩu quản trị, giới hạn log container, kernel hardening (`vm.max_map_count=262144`).
   - Tích hợp module `wazuh-integratord` để liên kết Threat Intelligence và gửi cảnh báo ChatOps.
2. **Giám sát Endpoint (Máy Windows 10 Pro):**
   - Được cài đặt **Wazuh Agent 4.14.5** phối hợp cùng **Microsoft Sysmon v15.2** (sử dụng file cấu hình tùy chỉnh) nhằm bắt trọn các hành vi ở tầng nhân (kernel) và tiến trình hệ thống.
   - Đã cấu hình FIM (File Integrity Monitoring) với cơ chế realtime trên các thư mục quan trọng.
3. **Nền tảng Tấn công (Máy Kali Linux):**
   - Sử dụng để giả lập các kỹ thuật tấn công của tin tặc (`xfreerdp`, `curl`, payload LFI) hướng vào máy Windows 10 nhằm sinh log kiểm thử.

---

## 🗂️ Cấu trúc Thư mục Repo

```text
wazuh-soc-lab/
│
├── README.md               # Tài liệu tổng quan hệ thống
├── documents/              # Tài liệu lý thuyết và lệnh thường dùng
│
├── architecture/           # Chứa ảnh sơ đồ mạng (mô hình topology)
│
├── deployment/             # Hướng dẫn và file cấu hình triển khai
│   ├── docker-compose.yml  # Triển khai Wazuh Manager, Indexer, Dashboard
│   └── sysmon-config.xml   # Cấu hình Sysmon v15.2 tối ưu
│
├── custom-rules/           # Chứa các rule và decoder tùy chỉnh
│   ├── local_rules.xml     # Rules phát hiện RDP Brute Force, Web LFI, Active Response
│   └── local_decoder.xml   # Decoder bóc tách log Apache Web Server
│
├── integrations/           # Phân hệ tích hợp mở rộng
│   ├── telegram/           # ChatOps cảnh báo thời gian thực về Telegram Bot
│   └── virustotal/         # Tự động tra cứu danh tiếng file lạ qua VirusTotal API
│
├── playbooks/              # Quy trình chuẩn ứng phó sự cố (SOP) theo NIST / SANS
│   ├── README.md           # Hướng dẫn vận hành và ma trận phân loại sự cố
│   ├── SOP-01_RDP_Brute_Force_Response.md
│   └── SOP-02_Web_LFI_Mitigation.md
│
├── tests/                  # Bộ công cụ tự động hóa kiểm thử (Detection-as-Code)
│   ├── e2e/                # Kịch bản kiểm thử End-to-End từ Attacker -> Victim -> SIEM
│   └── unit/               # Kiểm thử cú pháp XML Rules và Decoders
│
└── reports/                # File báo cáo chi tiết các giai đoạn triển khai
    ├── Phase-1_Infrastructure-Deployment.md
    ├── Phase-2_Agent-Sysmon-Configuration.md
    ├── Phase-3_Scenario-1.md
    ├── Phase-3_Scenario-2.md
    ├── Phase-4_Regression-Test-Automation.md
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


### 🔹 Kịch bản 3: T1027 / T1204 - PHÁT HIỆN TỆP TIN ĐỘC HẠI BẰNG THREAT INTELLIGENCE (VIRUSTOTAL API)
* **Mô hình thử nghiệm:** Thả file mã độc mẫu chuẩn quốc tế EICAR vào các thư mục giám sát (`C:\Users\Public`).
* **Thu thập Telemetry (Log):** Module FIM (Syscheck) phát hiện tệp tin mới tạo và tự động tính toán mã băm SHA256/MD5.
* **Chiến lược phát hiện:** `wazuh-integratord` gửi mã băm lên VirusTotal Cloud API đối soát với >70 Antivirus Engines. Khi có >= 1 Engine báo độc, tự động kích hoạt **Rule ID 87105 (Level 12 - High Severity)**.
* **Minh chứng & Hướng dẫn:** Xem chi tiết tại [integrations/virustotal/README.md](integrations/virustotal/README.md).

---

## 🤖 Tích hợp ChatOps: Cảnh báo Thời Gian Thực về Telegram

Hệ thống đã được trang bị phân hệ ChatOps hoàn chỉnh, giúp đội ngũ SOC tiếp nhận và phân tích cảnh báo tức thì ngay trên Telegram:

* **Tự động bóc tách & định dạng:** Script tích hợp tùy chỉnh ([`custom-telegram.py`](integrations/telegram/custom-telegram.py)) xử lý alert JSON từ Wazuh Manager, trích xuất đầy đủ: IP Kẻ tấn công, tài khoản mục tiêu, Endpoint bị ảnh hưởng, Rule ID, mức độ nghiêm trọng và ánh xạ chiến thuật/kỹ thuật theo **MITRE ATT&CK**.
* **Thẻ cảnh báo trực quan:** Sử dụng HTML Rich Formatting kèm các icon phân cấp mức độ (🚨 Critical / ⚠️ Medium / 🛡️ Active Response).
* **Quy tắc tự động kích hoạt cảnh báo:**
  * **Rule 100001:** Cảnh báo tấn công RDP Brute Force dồn dập.
  * **Rule 100002:** Cảnh báo tấn công khai thác lỗ hổng Web LFI.
  * **Rule 87105:** Cảnh báo VirusTotal phát hiện tệp tin độc hại.
* **Hướng dẫn cấu hình & kiểm thử:** Xem chi tiết tại [integrations/telegram/README.md](integrations/telegram/README.md).

---

## 📋 Quy trình Chuẩn Ứng phó Sự cố (Incident Response Playbooks / SOP)

Nhằm đáp ứng tiêu chuẩn vận hành an ninh chuyên nghiệp của Trung tâm Điều hành An ninh mạng (SOC), hệ thống được trang bị bộ tài liệu SOP chuẩn hóa theo khuyến nghị **NIST SP 800-61 Rev. 2** và chu trình **SANS PICERL** (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned):

1. **[SOP-01: RDP Brute Force Response](playbooks/SOP-01_RDP_Brute_Force_Response.md):**
   - Tiêu chí phân loại sự cố (Triage Severity Matrix).
   - Kiểm tra nguy cơ tài khoản bị chiếm đoạt thành công (Windows Event ID 4624 - Logon Type 10).
   - Hướng dẫn cô lập thủ công khi Active Response gặp sự cố (Fallback Containment).
   - Biện pháp củng cố an ninh hậu sự cố (GPO Account Lockout Threshold, NLA, đổi cổng RDP mặc định).

2. **[SOP-02: Web LFI & Path Traversal Mitigation](playbooks/SOP-02_Web_LFI_Mitigation.md):**
   - Phân tích Apache Access Logs và chuỗi payload độc hại.
   - Rà soát Web Shell và tiến trình con bất thường bằng **Sysmon Event ID 1 & Event ID 11**.
   - Hướng dẫn vá lỗ hổng code PHP (áp dụng Whitelist validation và hàm `basename()`).
   - Củng cố máy chủ Web (phân quyền thư mục `htdocs`, cấm thực thi script trong thư mục upload).

> 📘 Xem toàn bộ kiến trúc quy trình và ma trận leo thang tại [playbooks/README.md](playbooks/README.md).

---

## 🛠️ Hướng dẫn Cài đặt & Triển khai
Xem chi tiết các bước tại các tài liệu chuyên đề:
1. Triển khai hạ tầng Wazuh Stack: `reports/Phase-1_Infrastructure-Deployment.md`
2. Cấu hình Agent và Sysmon: `reports/Phase-2_Agent-Sysmon-Configuration.md`
3. Triển khai kịch bản tấn công và phát hiện: `reports/Phase-3_Scenario-1.md` và `reports/Phase-3_Scenario-2.md`
4. Tự động hóa kiểm thử hồi quy (Detection-as-Code): `reports/Phase-4_Regression-Test-Automation.md`
5. Tích hợp Threat Intelligence (VirusTotal): [integrations/virustotal/README.md](integrations/virustotal/README.md)
6. Tích hợp ChatOps cảnh báo Telegram: [integrations/telegram/README.md](integrations/telegram/README.md)
7. Quy trình ứng phó sự cố SOC: [playbooks/README.md](playbooks/README.md)

### Điều kiện tiên quyết:
*   Phần mềm máy ảo: VMware Workstation hoặc VirtualBox.
*   Tài nguyên phần cứng khuyến nghị:
  - Ubuntu Server: Ít nhất 2 vCPU, 4GB RAM, 65GB SSD.
  - Windows 10: Ít nhất 2 vCPU, 2GB RAM.

---

## 📊 Kỹ năng Thực tế Đạt được qua Đồ án này
*   **Quản trị và Vận hành SIEM/XDR:** Nắm vững kiến trúc hệ thống, cài đặt phân hệ Agent, quản lý luồng log nạp vào.
*   **Kỹ nghệ Phát hiện Tấn công (Detection Engineering):** Thành thạo kỹ năng viết luật bằng XML, thiết kế bộ giải mã decoder, sử dụng biểu thức chính quy (Regex) và tối ưu giảm thiểu cảnh báo giả (False-Positive).
*   **Phân tích Telemetry Máy trạm (Endpoint):** Hiểu sâu sắc cơ chế ghi log Windows Event Logs, cấu trúc bảng dữ liệu nâng cao của Sysmon v15.2 và phân hệ FIM.
*   **Tự động hóa Phòng thủ (SOAR & Active Response):** Kích hoạt phản ứng tự động cô lập máy chủ qua tường lửa (`netsh`) và tích hợp luồng cảnh báo tức thì qua Telegram ChatOps.
*   **Tình báo Mối đe dọa (Threat Intelligence):** Khai thác VirusTotal API phục vụ tra cứu danh tiếng mã độc tự động theo thời gian thực.
*   **Quy trình Vận hành SOC (Incident Response):** Nắm vững quy chuẩn ứng phó sự cố theo khung NIST SP 800-61 / SANS PICERL.

---

## 📚 Tài liệu tham khảo
- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference/overview)
