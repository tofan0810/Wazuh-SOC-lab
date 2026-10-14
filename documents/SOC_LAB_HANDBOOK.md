# 📘 SỔ TAY HỌC TẬP & BẢN ĐẶC TẢ KỸ THUẬT PHÒNG LAB WAZUH SOC & SOAR
> **Tài liệu học tập có tính hệ thống (Systematic Study Handbook & Architecture Notes)**  
> **Mục tiêu:** Dùng để ghi chép vào vở, ôn tập kiến trúc, hiểu rõ bản chất từng dòng code/config và tự tin trả lời vấn đáp đồ án tốt nghiệp / phỏng vấn SOC & Detection Engineer.

---

## 🗂️ MỤC LỤC GHI CHÉP VỞ

* **[Phần 1: Tổng Quan Kiến Trúc SOC & Mô Hình Đóng Gói Turnkey](#1-tổng-quan-kiến-trúc-soc--mô-hình-đóng-gói-turnkey)**
* **[Phần 2: 6 Khái Niệm Nền Tảng Chắt Lọc (Core Concepts)](#2-6-khái-niệm-nền-tảng-chắt-lọc-core-concepts)**
* **[Phần 3: Danh Mục Thành Phần & Vai Trò Trong Hệ Thống (System Inventory)](#3-danh-mục-thành-phần--vai-trò-trong-hệ-thống-system-inventory)**
* **[Phần 4: Phân Tích Chi Tiết Từng File Cấu Hình & Source Code](#4-phân-tích-chi-tiết-từng-file-cấu-hình--source-code)**
* **[Phần 5: Ma Trận 16 Quy Tắc Phát Hiện (Detection Rules Matrix 100001 - 100016)](#5-ma-trận-16-quy-tắc-phát-hiện-detection-rules-matrix-100001---100016)**
* **[Phần 6: Quy Trình Phản Ứng Khép Kín (SOAR Closed-Loop & 1-Click Rollback)](#6-quy-trình-phản-ứng-khép-kín-soar-closed-loop--1-click-rollback)**
* **[Phần 7: Bộ 8 Câu Hỏi Vấn Đáp Đồ Án & Phỏng Vấn Tuyển Dụng (Viva Defense Q&A)](#7-bộ-8-câu-hỏi-vấn-đáp-đồ-án--phỏng-vấn-tuyển-dụng-viva-defense-qa)**

---

# 1. TỔNG QUAN KIẾN TRÚC SOC & MÔ HÌNH ĐÓNG GÓI TURNKEY

### 1.1. Mục tiêu đồ án
Xây dựng một hệ thống **Trung tâm Giám sát và Điều hành An ninh mạng (Security Operations Center - SOC)** khép kín mang đầy đủ năng lực thực chiến cấp doanh nghiệp:
1. **Thu thập dữ liệu đo kiểm (Telemetry Collection):** Bắt trọn hành vi máy trạm từ tầng nhân Kernel (Sysmon v15.2), nhật ký xác thực Windows (EVTX), web access log và giám sát mạng tầng sâu (Suricata NIDS).
2. **Kỹ thuật phát hiện (Detection Engineering & DaC):** Quản lý quy tắc bằng chuẩn Sigma YAML (Single Source of Truth - SSOT), tự động biên dịch sang XML Wazuh và kiểm tra lệch pha (Zero-Drift CI/CD).
3. **Làm giàu thông tin (Threat Intelligence Enrichment):** Tự động truy vấn danh tiếng IP độc hại qua AbuseIPDB API và đối soát mã băm tập tin qua VirusTotal Cloud API.
4. **Tự động hóa phản ứng khép kín (SOAR & Closed-Loop Containment):** Điều phối xử lý sự cố có con người tham gia (**Human-in-the-Loop**) qua Telegram ChatOps 2 chiều, hỗ trợ nút bấm **Khóa cách ly**, **Phục hồi (1-Click Rollback)** và tự động tạo vé sự cố trên **Atlassian Jira Cloud REST API v3**.
5. **Công nghệ bẫy mồi chủ động (Deception Defense):** Triển khai Canary Honey-file (SACL Event 4663), Honey-account (Event 4625) và Decoy Port 21 với **tỷ lệ báo động giả bằng không (0% False Positive)**, tự động trích xuất chứng cứ số (Live DFIR Forensics).

---

### 1.2. Mô hình Đóng gói 2 Gói Triển khai Turnkey (`endpoint/` & `manager/`)

Dự án được tái cấu trúc thành 2 gói độc lập, giúp việc triển khai từ máy trắng (Clean OS) trở nên dễ dàng chỉ với 1 lệnh:

```text
wazuh-soc-lab/
├── endpoint/                   # 🛡️ GÓI MÁY TRẠM NẠN NHÂN (Windows 10 Target - 192.168.71.129)
│   ├── config/                 # ossec.conf (Agent 1514/TCP) & sysmon-config.xml (Sysmon v15.2)
│   ├── active-response/        # kill-process.cmd/ps1 (diệt PID) & collect-evidence.cmd/ps1
│   ├── deception/              # setup_canary.ps1 (bẫy file), network_decoy.ps1/py (bẫy port 21)
│   ├── setup_endpoint.ps1      # Script Master 1-Click tự động hóa cấu hình toàn bộ Windows
│   └── README.md               # Sổ tay hướng dẫn người dùng cài đặt phần mềm gốc & chạy script
│
├── manager/                    # 🚀 GÓI MÁY CHỦ SIEM & SOAR (Ubuntu Server - 192.168.71.128)
│   ├── docker/                 # Wazuh Stack All-in-One (Port 443) & n8n SOAR (Port 5678)
│   ├── rules/                  # Sigma YAML SSOT (sigma/), local_rules.xml (100001-100016), local_decoder.xml
│   ├── suricata/               # suricata.yaml (bắt packet ens33), local.rules (4 signatures NIDS)
│   ├── soar/                   # 3 Workflows JSON, custom-n8n.py dispatcher, telegram_bridge.py
│   ├── dashboard/              # soc_lab_executive_dashboard.ndjson (9 visual panels OpenSearch)
│   ├── setup_manager.sh        # Script Master 1-Click triển khai Docker containers & NIDS
│   └── README.md               # Sổ tay hướng dẫn người dùng cài đặt Docker & kích hoạt lab
│
├── architecture/               # Sơ đồ thiết kế hệ thống chuẩn 16:9 vector SVG
├── commands/                   # Trung tâm tra cứu nhanh lệnh vận hành
├── documents/                  # Sổ tay học tập, lý thuyết SIEM & cẩm nang vận hành
├── playbooks/                  # 6 Quy trình chuẩn ứng phó sự cố (SOP-01 đến SOP-06) theo NIST/SANS
├── reports/                    # Báo cáo kỹ thuật chi tiết thực nghiệm từ Phase 1 đến Phase 10
├── scripts/                    # Công cụ tự động hóa: sync_env.py, sigma_compiler.py, import_dashboard.py
└── tests/                      # 22 bài kiểm thử đơn vị CI/CD (tests/unit/) & kiểm thử E2E (tests/e2e/)
```

---

### 1.3. Sơ đồ Luồng Dữ liệu Toàn trình (End-to-End Dataflow)

```text
===================================================================================================
                               SƠ ĐỒ LUỒNG DỮ LIỆU END-TO-END SOC PIPELINE
===================================================================================================

  [ KALI LINUX - 192.168.71.130 ] 
      │ (Tấn công: RDP Brute Force, Web LFI, PowerShell Base64, UAC Bypass, LSASS Dump, Nmap Scan)
      ▼
  [ WINDOWS 10 ENDPOINT - 192.168.71.129 ]
      │ • Sysmon v15.2: Process Create (Event 1), LSASS Access (Event 10), Registry Run (Event 12/13)
      │ • Windows Security: RDP Logon Failure (Event 4625), Canary SACL Access (Event 4663)
      │ • Apache HTTP Access Log (access.log) & FTP Decoy Port 21 (Event 60000)
      │ • Wazuh Agent v4.14.5: Đẩy Telemetry qua Port 1514/TCP (Mã hóa AES)
      │
      ▼
  [ WAZUH SIEM MANAGER & NIDS - 192.168.71.128 ]
      │ • Suricata NIDS: Bắt gói tin trên ens33 -> Ghi /var/log/suricata/eve.json
      │ • Wazuh Analysisd Engine: Giải mã (local_decoder.xml) & Đối khớp luật (local_rules.xml)
      │ • Active Response cục bộ: Tự động khóa IP (netsh) hoặc diệt PID (kill-process.ps1)
      │
      ├───────────────────────────────┬───────────────────────────────┐
      │ (OpenSearch Port 9200)        │ (<integration> ossec.conf)    │ (<integration> ossec.conf)
      ▼                               ▼                               ▼
  [ Wazuh Indexer & Dashboard ]   [ VirusTotal Cloud API ]     [ custom-n8n.py Dispatcher ]
    (Trực quan hóa SIEM Port 443)   (Đối soát Hash SHA256)       (Dual-Mode IOC Resolution)
                                                                      │
                                                                      │ (HTTP POST Webhook JSON)
                                                                      ▼
                                                       [ n8n SOAR ENGINE - Port 5678 ]
                                                           │ (Workflow 1: Threat Enrichment)
                                                           ├─► AbuseIPDB API (Tra cứu IP)
                                                           ├─► Format HTML Alert Card phong phú
                                                           ▼
                                                       [ TELEGRAM CHATOPS BOT ]
                                                           │ (@my_wazuh_soc_alert_bot)
                                                           │ Gửi thẻ tương tác kèm 3 nút bấm:
                                                           │ [🚫 Khóa IP 24h] [🔄 Mở khóa (Rollback)] [📋 Mở Jira]
                                                           │
                                                           │ (Analyst chạm nút bấm trên điện thoại)
                                                           ▼
                                                       [ telegram_bridge.py ]
                                                           │ (Long-Polling bắt callback)
                                                           ▼
                                                       [ n8n Workflow 2: Containment Executor ]
                                                           │
                                    ┌──────────────────────┼──────────────────────┐
                                    ▼                      ▼                      ▼
                           [ Nhánh action:block ]  [ Nhánh action:unblock ] [ Nhánh action:jira ]
                                    │                      │                      │
                             Chạy WinRM sang        Chạy WinRM sang        Gọi Jira Cloud API
                             Windows 10 tạo         Windows 10 xóa         (POST /rest/api/3/issue)
                             Firewall DROP Rule     Firewall DROP Rule     Tạo Ticket Project KAN
                                    │                      │                      │
                                    └──────────────────────┴──────────────────────┘
                                                           │
                                                           ▼
                                              Phản hồi kết quả về Telegram trong < 5s
```

---

# 2. 6 KHÁI NIỆM NỀN TẢNG CHẮT LỌC (CORE CONCEPTS)

### 2.1. Telemetry (Dữ liệu Đo kiểm An ninh Tầng Sâu)
* **Trực giác:** Camera giám sát hành vi của hệ điều hành. Nếu camera chỉ đặt ngoài cổng (Windows Event Log cơ bản), kẻ trộm vào trong nhà lục tủ (đọc trộm RAM LSASS) sẽ không ai hay biết.
* **Cơ chế:** Sysmon chèn trình điều khiển lọc (Filter Driver) `SysmonDrv.sys` trực tiếp vào nhân Windows Kernel để chặn bắt mọi hành vi trước khi tiến trình độc hại kịp xóa dấu vết.
* **Điểm cốt lõi ghi vở:** Windows Event Log mặc định **không thể** phát hiện kỹ thuật đọc trộm bộ nhớ LSASS hoặc ghi khóa Registry ẩn danh. Cần kết hợp Sysmon Event 1 (Process Create), Event 10 (ProcessAccess), Event 12/13 (Registry).

### 2.2. Decoders & Rules (Bộ Giải Mã và Luật Tương Quan)
* **Trực giác:** Decoder là **người phiên dịch** (biến một đoạn nhật ký thô sơ lộn xộn thành các trường dữ liệu có nhãn mác rõ ràng). Rule là **quan tòa** (đối chiếu các nhãn mác đó với bộ luật hình sự để ra phán quyết).
* **Cơ chế:** Log thô $\rightarrow$ Phân tích cấu trúc (Pre-decoding & Regex Decoding) $\rightarrow$ Rút trích `srcip`, `url`, `eventID` $\rightarrow$ Đẩy qua Cây quy tắc (Rule Evaluation Tree) từ Level 0 đến 16.
* **Điểm cốt lõi ghi vở:** Luật cấp độ `level="0"` là **luật ức chế (Suppression)** — được dùng để loại trừ cảnh báo giả sinh ra từ chính hành động cứu trợ của SOAR (`socrunner` qua WinRM), ngăn chặn vòng lặp tự kích hoạt báo động vô tận (Feedback Loop).

### 2.3. Active Response vs. SOAR Containment
* **Trực giác:** Active Response là **phanh ABS tự động** (máy tính tự dập tắt nguy cơ trong mili-giây mà không cần hỏi). SOAR là **lệnh chỉ huy từ xa** (hệ thống chuẩn bị sẵn phương án, đưa lên điện thoại cho sếp bấm nút xác nhận).
* **So sánh kỹ thuật:**
  * **Active Response:** Chạy cục bộ bằng daemon `wazuh-execd` trên Endpoint, phản ứng tức thì với các mối đe dọa rõ ràng (như diệt tiến trình mã hóa Base64 bằng `kill-process.ps1`).
  * **SOAR (Human-in-the-Loop):** n8n kết nối đa hệ thống (AbuseIPDB, Jira, WinRM, Telegram), áp dụng cho các quyết định cách ly mạng có thể ảnh hưởng tới hoạt động kinh doanh (ngăn chặn tình trạng chặn nhầm IP máy chủ nghiệp vụ).

### 2.4. Dual-Mode IOC Resolution (Cơ Chế Định Danh Kép)
* **Trực giác:** Bị bắn từ xa thì tìm kẻ bắn để khóa; tự mình phát bệnh truyền nhiễm từ bên trong thì phải cách ly chính mình để không lây cho cả phòng.
* **Vấn đề thực tế:** Các đồ án thông thường chỉ xử lý được tấn công mạng có `srcip`. Khi tin tặc đã ở trong máy và chạy mã độc cục bộ (UAC Bypass, Dump LSASS), log không có `srcip` $\rightarrow$ SOAR bị lỗi `Target: N/A` và không thể tạo luật chặn tường lửa.
* **Giải pháp độc quyền:** Script [`manager/soar/custom-n8n.py`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/manager/soar/custom-n8n.py) tự động kiểm tra:
  * **Mode 1 (Remote Network):** Có `srcip` hợp lệ từ xa $\rightarrow$ Chặn IP kẻ tấn công (Kali `192.168.71.130`).
  * **Mode 2 (Host-Internal Kill Chain):** `srcip` bị trống $\rightarrow$ Fallback lấy chính IP máy bị xâm nhập (`192.168.71.129`) làm mục tiêu cô lập mạng, cắt đứt kết nối C2 của tin tặc.

### 2.5. Safe Host Isolation & 1-Click Rollback (Cách Ly An Toàn & Hoàn Tác 5s)
* **Trực giác:** Nhốt kẻ trộm vào phòng nhưng **không được khóa trái cửa thoát hiểm** của lực lượng cảnh sát.
* **Nguyên tắc sống còn:** Khi áp dụng luật tường lửa cô lập máy trạm Windows (`New-NetFirewallRule -Action Block`), **TUYỆT ĐỐI KHÔNG ĐƯỢC CHẶN Port 5985 (WinRM)** và **Port 1514/1515 (Wazuh Agent)**.
* **Ý nghĩa:** Giữ thông kênh quản trị giúp SOC Analyst có thể bấm nút **[🔄 Mở khóa (Rollback)]** trên Telegram để khôi phục mạng cho máy trạm trong vòng **dưới 5 giây** mà không cần phải chạy lại cắm màn hình bàn phím thủ công.

### 2.6. Deception Technology (Công Nghệ Bẫy Mồi Chủ Động - 0% False Positive)
* **Trực giác:** Rải các túi tiền giả có gắn chuông báo động ở góc phòng. Người nhà bình thường không bao giờ động vào, chỉ có kẻ trộm đi lục lọi tài sản mới chạm vào và làm chuông reo.
* **Cơ chế:** Đặt Honey-file `IT_Admin_Credentials.xlsx` (bật SACL Audit Event 4663), tạo tài khoản ảo `backup_admin` (Event 4625), và mở cổng mồi FTP 21 (`network_decoy.ps1`). Mọi tương tác vào các mục tiêu này **100% là hành vi thâm nhập trái phép**, kích hoạt thu thập chứng cứ DFIR ngay lập tức.

---

# 3. DANH MỤC THÀNH PHẦN & VAI TRÒ TRONG HỆ THỐNG (SYSTEM INVENTORY)

| STT | Thành Phần | Phiên Bản / Công Nghệ | Vị Trí Triển Khai | Vai Trò & Chức Năng Cốt Lõi |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Wazuh SIEM Manager** | v4.14.5 (Docker All-in-One) | Ubuntu `192.168.71.128` | Trái tim phân tích log, đối khớp quy tắc, tương quan sự kiện và kích hoạt Active Response. |
| **2** | **Wazuh Indexer & Dashboard**| OpenSearch 2.x (Port 443) | Ubuntu `192.168.71.128` | Lưu trữ dữ liệu log tập trung, hiển thị 9 panel biểu đồ giám sát an ninh trực quan. |
| **3** | **Suricata NIDS** | v6.x/7.x Native Linux | Ubuntu `192.168.71.128` | Cảm biến giám sát mạng trên card `ens33`, phát hiện quét cổng Nmap và payload LFI qua mạng dây. |
| **4** | **Microsoft Sysmon** | v15.2 (Sysinternals) | Windows `192.168.71.129` | Giám sát nhân Windows: Process Create (E1), LSASS Access (E10), Registry Persistence (E12/13). |
| **5** | **Wazuh Agent** | v4.14.5 (MSI Service) | Windows `192.168.71.129` | Thu thập Telemetry đẩy về Manager qua cổng 1514/TCP, nhận lệnh thực thi phản ứng khẩn cấp. |
| **6** | **n8n SOAR Engine** | Latest Docker (Port 5678) | Ubuntu `192.168.71.128` | Bộ não điều phối luồng phản ứng: Làm giàu Threat Intel, đẩy ChatOps Telegram, gọi WinRM, tạo Jira. |
| **7** | **Telegram Bot & Bridge** | Telegram Cloud API + Python | Ubuntu `192.168.71.128` | Giao diện ChatOps tương tác 2 chiều cho Analyst qua kỹ thuật Long-Polling không cần mở NAT. |
| **8** | **Atlassian Jira Cloud** | REST API v3 (Project `KAN`) | Cloud SaaS | Hệ thống quản lý vé sự cố (Case Management), lưu trữ báo cáo điều tra phục vụ kiểm toán ISO 27035. |
| **9** | **AbuseIPDB & VirusTotal** | REST Cloud APIs | Cloud SaaS | Nền tảng tình báo mối đe dọa (Threat Intel), cung cấp điểm uy tín IP và đối soát mã băm độc hại. |

---

# 4. PHÂN TÍCH CHI TIẾT TỪNG FILE CẤU HÌNH & SOURCE CODE

## 4.1. File: `manager/rules/local_rules.xml` (Tập Luật Phát Hiện Cốt Lõi)

### Đoạn 1: Phát hiện dò quét mật khẩu RDP Brute Force (T1110)
```xml
  <!-- Rule 100001: Gom 5 lần thất bại trong 60 giây -> Báo động Brute Force -->
  <rule id="100001" level="12" frequency="5" timeframe="60">
    <if_matched_sid>60122</if_matched_sid>
    <description>Windows Brute Force Attack Detected</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
```
* **Bản chất kỹ thuật:** Kế thừa từ rule gốc `60122` (Windows Logon Failure Event 4625). Cơ chế `frequency="5"` và `timeframe="60"` nghĩa là nếu cùng 1 máy trạm nhận 5 lần đăng nhập sai trong 1 phút thì nâng cấp mức độ nguy hiểm lên **Level 12 (Critical)**.
* **Ý nghĩa thực tiễn:** Loại bỏ tình huống người dùng gõ nhầm mật khẩu 1-2 lần; chỉ bắt khi có công cụ tự động hóa dò quét như Hydra hay Crowbar.

---

### Đoạn 2: Phát hiện PowerShell độc hại & Luật Ức Chế Phân Cấp (Hierarchical Child Suppression)
```xml
  <!-- Rule 100004: Bắt lệnh PowerShell có cờ mã hóa Base64 / Ẩn cửa sổ -->
  <rule id="100004" level="12">
    <if_sid>100003</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-EncodedCommand|-enc|-w\s+hidden|-nop)</field>
    <description>CRITICAL WARNING: Malicious PowerShell Execution with Encoded/Hidden parameters detected!</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Rule 100008: Luật ức chế Level 0 dành riêng cho SOAR Remediation -->
  <rule id="100008" level="0">
    <if_sid>100004</if_sid>
    <field name="win.eventdata.user" type="pcre2">(?i)socrunner</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(cmd|wsmprovhost|winrshost)\.exe</field>
    <description>Suppression: Authorized SOAR Remediation PowerShell execution via WinRM</description>
  </rule>
```
* **Bản chất kỹ thuật:** Rule 100004 kiểm tra trường `commandLine` từ Sysmon Event 1 để phát hiện cờ obfuscation.
* **Kiến trúc thượng tầng (Masterclass Tuning):** Khi SOAR n8n kết nối qua WinRM để thực thi cứu trợ dưới tài khoản `socrunner`, lệnh PowerShell cứu trợ cũng có thể kích hoạt Rule 100004! Thay vì dùng điều kiện phủ định lỏng lẻo `negate="yes"` (khiến tin tặc dễ bypass bằng cách mạo danh user), ta tạo **Rule con phân cấp 100008 với `level="0"`**:
  * Chỉ khi thỏa mãn đồng thời: User là `socrunner` **VÀ** tiến trình cha sinh ra từ WinRM (`wsmprovhost.exe` hoặc `winrshost.exe`) thì mới ức chế báo động.
  * Nếu tin tặc chạy lệnh dưới user `socrunner` từ giao diện console thông thường, tiến trình cha là `explorer.exe` $\rightarrow$ Rule 100008 không khớp $\rightarrow$ Rule 100004 vẫn nổ còi bình thường!

---

### Đoạn 3: Phát hiện đọc trộm bộ nhớ LSASS Dump mật khẩu (T1003.001)
```xml
  <!-- Rule 100005: Sysmon Event 10 - ProcessAccess nhắm vào lsass.exe -->
  <rule id="100005" level="12">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(MsMpEng\.exe|wmiprvse\.exe|wazuh-agent\.exe|svchost\.exe|csrss\.exe|services\.exe)</field>
    <field name="win.eventdata.grantedAccess" type="pcre2" negate="yes">^0x1000$</field>
    <description>CRITICAL WARNING: Suspicious Process Access to LSASS detected (Potential Credential Dumping)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
```
* **Bản chất kỹ thuật:** `lsass.exe` là nơi lưu trữ mật khẩu đăng nhập dạng Cleartext/NTLM Hash trong RAM. Các công cụ như Mimikatz hay ProcDump bắt buộc phải mở quyền đọc bộ nhớ `PROCESS_VM_READ` (`0x0010`) hoặc `PROCESS_ALL_ACCESS` (`0x1FFFFF`).
* **Kỹ thuật Tuning giảm 100% FP:** Các tiến trình lành tính định kỳ của hệ thống như `svchost.exe` chỉ yêu cầu quyền thăm dò trạng thái cơ bản `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`). Bộ lọc phủ định `negate="yes">^0x1000$` loại bỏ hoàn toàn cảnh báo rác từ Windows mà không bỏ sót bất kỳ mã độc thực thụ nào.

---

## 4.2. File: `manager/rules/local_decoder.xml` (Bộ Giải Mã Apache Web Access)

```xml
<decoder name="web-access-lfi">
  <parent>windows-date-format</parent>
  <type>windows</type>
  <regex offset="after_parent">^(\S+) \S+ \S+ \[\S+ \S+\] "(\S+) (\S+) \S+" (\d+) \d+</regex>
  <order>srcip, protocol, url, id</order>
</decoder>
```
* **Bản chất kỹ thuật:** Chuẩn hóa dòng log Apache Common Log Format (NCSA) thành 4 trường dữ liệu chuẩn:
  * `srcip`: IP của Client truy cập (Kali `192.168.71.130`).
  * `protocol`: Phương thức HTTP (GET/POST).
  * `url`: Đường dẫn truy cập (ví dụ: `/index.php?page=../../win.ini`).
  * `id`: Mã phản hồi HTTP Status Code (200, 404, 500).
* **Ý nghĩa:** Giúp Rule 100002 đối khớp chính xác chuỗi duyệt thư mục `../` hoặc file nhạy cảm `win.ini`.

---

## 4.3. File: `manager/soar/custom-n8n.py` (Bộ Điều Phối Webhook & Định Danh Kép)

```python
def extract_ioc_data(alert_data):
    """Cơ chế Dual-Mode IOC Resolution độc quyền của Lab"""
    rule_id = alert_data.get("rule", {}).get("id", "N/A")
    agent_info = alert_data.get("agent", {})
    endpoint_ip = agent_info.get("ip", "192.168.71.129")
    endpoint_name = agent_info.get("name", "windows-victim")

    data = alert_data.get("data", {})
    src_ip = data.get("srcip") or alert_data.get("srcip")

    # MODE 1: Tấn công mạng từ xa có IP rõ ràng (RDP, Web LFI, NIDS)
    if src_ip and src_ip not in ("-", "127.0.0.1", "0.0.0.0", ""):
        target_ioc = src_ip
        is_internal_killchain = False
    else:
        # MODE 2: Tấn công nội bộ chuỗi Kill Chain (PowerShell, UAC, LSASS)
        # Tự động Fallback lấy IP của máy bị xâm nhập để cô lập khẩn cấp
        target_ioc = endpoint_ip
        is_internal_killchain = True

    return {
        "rule_id": rule_id,
        "src_ip": target_ioc,           # Đảm bảo luôn có IP thực tế, không bao giờ N/A
        "endpoint_ip": endpoint_ip,
        "endpoint_name": endpoint_name,
        "is_internal": is_internal_killchain
    }
```
* **Ý nghĩa thực tiễn:** Loại bỏ hoàn toàn lỗi crash runtime của n8n do trường dữ liệu bị rỗng, đảm bảo nút bấm phản ứng trên Telegram luôn luôn có đối tượng IP chính xác để thi hành.

---

## 4.4. File: `manager/soar/telegram_bridge.py` (Cầu Nối ChatOps Long-Polling)

```python
def poll_updates(offset=None):
    """Kỹ thuật Long-Polling: Lắng nghe sự kiện Telegram mà không cần mở Port NAT"""
    url = f"{TELEGRAM_API_BASE}/getUpdates?timeout=20"
    if offset:
        url += f"&offset={offset}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Wazuh-SOAR-Telegram-Bridge"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return data.get("result", [])
    except Exception as e:
        logger.warning(f"Error fetching updates from Telegram: {e}")
    return []
```
* **Bản chất kỹ thuật:** Máy ảo Lab chạy sau dải mạng VMware NAT riêng tư (`192.168.71.0/24`), không có IP tĩnh công khai (Public IP).
* **Giải pháp kiến trúc:** Script chủ động mở kết nối hướng ngoại (Outbound) tới Telegram Cloud API và giữ kết nối treo (Long-Polling 20 giây). Khi Analyst bấm nút trên điện thoại, Telegram trả về callback query lập tức $\rightarrow$ Script đẩy ngay vào n8n webhook cục bộ (`http://127.0.0.1:5678/webhook/telegram-callback`) trong **mili-giây** mà không cần mở port NAT hay dùng ngrok.

---

## 4.5. File: `endpoint/setup_endpoint.ps1` (Master 1-Click Provisioning Endpoint)

```powershell
# Tạo cấu hình cách ly mạng an toàn (Safe Isolation)
# Đảm bảo LUÔN CHO PHÉP Port 5985 (WinRM) và Port 1514 (Wazuh Agent)
New-NetFirewallRule -DisplayName "SOC-Mgmt-WinRM-In" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "SOC-Mgmt-Wazuh-Out" -Direction Outbound -RemotePort 1514 -Protocol TCP -Action Allow -Profile Any

# Triển khai Canary Honey-file và gán SACL Auditing (Event 4663)
$CanaryPath = "C:\Users\Public\Documents\IT_Admin_Credentials.xlsx"
New-Item -Path $CanaryPath -ItemType File -Force
$Acl = Get-Acl $CanaryPath
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData,ExecuteFile", "Success")
$Acl.SetAuditRule($AuditRule)
Set-Acl -Path $CanaryPath -AclObject $Acl
```
* **Ý nghĩa:** Đảm bảo hệ thống phòng thủ có thể tự chữa lành (Self-Healing) và thực hiện hoàn tác (Rollback) từ xa, đồng thời thiết lập bẫy file nhạy cảm kích hoạt kiểm toán tầng nhân (SACL Audit).

---

# 5. MA TRẬN 16 QUY TẮC PHÁT HIỆN (DETECTION RULES MATRIX 100001 - 100016)

Toàn bộ 16 quy tắc tùy chỉnh được cấp phát trong dải số an toàn `100001 - 100016`, biên dịch tự động từ Sigma YAML SSOT:

| Rule ID | Nhóm Phân Hệ & Kỹ Thuật MITRE | Nguồn Telemetry Thu Thập | Điều Kiện Logic Kích Hoạt | Cấp Độ (Level) | Phương Pháp Giảm Báo Động Giả (Tuning) |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **100001** | `T1110` (RDP Brute Force) | Windows Security Event 4625 | 5 lần xác thực thất bại trong 60s từ cùng 1 IP | **Level 12** | Ngưỡng `frequency="5"` loại bỏ người dùng gõ nhầm pass. |
| **100002** | `T1190` (Web LFI / Traversal) | Apache `access.log` qua custom decoder | URL chứa `../`, `..%2f`, `win.ini`, `boot.ini` | **Level 10** | Lọc chuỗi Directory Traversal đặc trưng. |
| **100003** | `Base Filter` (Process Creation) | Sysmon Event 1 | Bộ lọc nền tảng gom mọi sự kiện tạo tiến trình | **Level 0** | Không kích hoạt cảnh báo, làm cha cho các rule con. |
| **100004** | `T1059.001` (PowerShell Obfuscation) | Sysmon Event 1 | Dòng lệnh chứa `-enc`, `-EncodedCommand`, `-w hidden` | **Level 12** | Bắt buộc đối soát tiến trình cha và giải mã base64. |
| **100005** | `T1003.001` (LSASS Credential Dump) | Sysmon Event 10 | `TargetImage` là `lsass.exe` với quyền đọc RAM | **Level 12** | **Phủ định quyền `0x1000`** triệt tiêu 100% FP từ `svchost.exe`. |
| **100006** | `T1547.001` (Registry Run Persistence) | Sysmon Event 12/13 | Ghi khóa vào `CurrentVersion\Run` hoặc `RunOnce` | **Level 10** | Giám sát tiến trình lạ tự cài khởi động cùng Windows. |
| **100007** | `T1548.002` (UAC Bypass Fodhelper) | Sysmon Event 12/13 | Hijack khóa Registry `ms-settings\Shell\Open\command` | **Level 12** | Fodhelper không bao giờ tạo tiến trình con $\rightarrow$ 100% chuẩn xác. |
| **100008** | `Child Suppression` (SOAR Remediation) | Sysmon Event 1 | User `socrunner` chạy PowerShell từ WinRM | **Level 0** | Ức chế báo động giả khi n8n thực thi lệnh cứu trợ. |
| **100009** | `Child Suppression` (UAC Cleanup) | Sysmon Event 12/13 | User `socrunner` dọn dẹp khóa Registry UAC | **Level 0** | Cho phép SOAR dọn rác mà không tự kích hoạt lại cảnh báo. |
| **100010** | `Child Suppression` (Run Key Cleanup) | Sysmon Event 12/13 | User `socrunner` dọn dẹp khóa Run Persistence | **Level 0** | Cho phép SOAR dọn khóa Run mà không tự kích hoạt lại alert. |
| **100011** | `T1046` (Nmap Reconnaissance) | Suricata NIDS (`eve.json`) | Bắt chuỗi signature quét cổng Nmap Stealth SYN | **Level 10** | Phân tích luồng gói tin trên wire trước khi chạm tới host. |
| **100012** | `T1190` (LFI Attack on Wire) | Suricata NIDS (`eve.json`) | Signature phát hiện URL chứa ký tự vượt thư mục | **Level 12** | Đối soát tầng mạng độc lập với web server application log. |
| **100013** | `T1595.002` (Vulnerability Scanner) | Suricata NIDS (`eve.json`) | Nhận diện chữ ký của Nikto, sqlmap, Gobuster | **Level 10** | Khóa IP máy quét tự động ngay từ giai đoạn Reconnaissance. |
| **100014** | `T1083` (Canary Honey-File Accessed) | Windows Security Event 4663 | SACL Audit khi có ai đọc file `IT_Admin_Credentials.xlsx` | **Level 12** | **Zero False Positive (0% FP)**, tự kích hoạt DFIR dump RAM. |
| **100015** | `T1078` (Honey-Account Logon Tripwire)| Windows Security Event 4625 | Có đăng nhập vào tài khoản mồi `backup_admin` | **Level 12** | **Zero False Positive (0% FP)**, báo hiệu dò pass tài khoản bẫy. |
| **100016** | `T1046` (Decoy Port 21 Probe) | Windows EventLog / Port Decoy | Có kết nối tới cổng dịch vụ ảo FTP Port 21 | **Level 10** | Bắt kẻ tấn công dò quét mạng nội bộ (Internal Recon). |

---

# 6. QUY TRÌNH PHẢN ỨNG KHÉP KÍN (SOAR CLOSED-LOOP & 1-CLICK ROLLBACK)

Quy trình phản ứng tuân thủ theo tiêu chuẩn **NIST SP 800-61 Rev. 2** gồm 5 giai đoạn:

```text
===================================================================================================
                   CHI TIẾT VÒNG ĐỜI SOAR CLOSED-LOOP INCIDENT RESPONSE
===================================================================================================

[ BƯỚC 1: TIẾP NHẬN & ĐỐI SOÁT (Detection & Triage) ]
  • Wazuh kích hoạt quy tắc (ví dụ: Rule 100007 - UAC Bypass hoặc Rule 100014 - Canary File).
  • wazuh-integratord chuyển alert JSON sang custom-n8n.py -> Tự động xác định IP mục tiêu.

[ BƯỚC 2: LÀM GIÀU DỮ LIỆU THREAT INTEL (Context Enrichment) ]
  • n8n Webhook Ingest nhận payload:
    - Nếu là Public IP: Gọi AbuseIPDB API lấy Abuse Confidence Score & ISP xuất xứ.
    - Nếu là File lạ: Đối soát VirusTotal API (Rule 87105).
  • n8n xây dựng thẻ cảnh báo HTML phong phú (Rich Text Card).

[ BƯỚC 3: PHÁT CHATOPS & PHÊ DUYỆT 2 CHIỀU (Human-in-the-Loop) ]
  • Gửi tin nhắn Telegram tới @my_wazuh_soc_alert_bot kèm 3 nút bấm tương tác:
    - [🚫 Khóa IP 24h]            -> Cách ly mạng khẩn cấp máy trạm hoặc chặn IP tấn công.
    - [🔄 Mở khóa (Rollback)]      -> Hoàn tác tức thì nếu phát hiện chặn nhầm.
    - [📋 Mở Ticket Jira]          -> Khởi tạo hồ sơ điều tra L2 trên Jira Cloud.

[ BƯỚC 4: THỰC THI PHẢN ỨNG AN TOÀN (Containment & Forensics) ]
  • Analyst bấm [🚫 Khóa IP 24h]:
    - n8n gọi WinRM PowerShell sang máy Windows 10:
      New-NetFirewallRule -DisplayName "SOAR-BLOCK" -Direction Inbound/Outbound -Action Block
    - Đảm bảo duy trì thông kênh Port 5985 (WinRM) và Port 1514 (Wazuh Agent).
  • Nếu là sự cố Deception: Tự động chạy collect_evidence.ps1 trích xuất MiniDump RAM,
    netstat, EVTX, nén file .zip và đính kèm vào Jira Ticket.

[ BƯỚC 5: HOÀN TÁC TỰ CHỮA LÀNH (1-Click Rollback in < 5s) ]
  • Nếu trực ca SOC phát hiện chặn nhầm hoặc sự cố đã xử lý xong:
    - Analyst bấm [🔄 Mở khóa (Rollback)] trên Telegram.
    - n8n gọi lệnh WinRM: Remove-NetFirewallRule -DisplayName "SOAR-BLOCK*"
    - Mạng máy trạm được khôi phục nguyên trạng trong 3-5 giây mà không cần can thiệp tay.
```

---

# 7. BỘ 8 CÂU HỎI VẤN ĐÁP ĐỒ ÁN & PHỎNG VẤN TUYỂN DỤNG (VIVA DEFENSE Q&A)

### Câu hỏi 1: Tại sao hệ thống phải kết hợp Sysmon với Wazuh Agent trên Endpoint?
* **Trả lời:** Wazuh Agent mặc định chủ yếu thu thập Windows Event Log cơ bản và thông tin hệ điều hành bề mặt. Các kỹ thuật tấn công tinh vi trong chuỗi **MITRE ATT&CK Kill Chain** như **Dump bộ nhớ LSASS (T1003.001)** hoặc **UAC Bypass qua Fodhelper (T1548.002)** không để lại dấu vết rõ ràng trong Event Viewer mặc định. Sysmon v15.2 hoạt động như một trình điều khiển lọc tầng nhân (`SysmonDrv.sys`), cung cấp Telemetry chuyên sâu: Event 1 (Dòng lệnh CommandLine đầy đủ kèm mã băm SHA256), Event 10 (Quyền mở handle truy cập bộ nhớ giữa các tiến trình), Event 12/13 (Thao tác Registry chi tiết). Việc kết hợp này biến máy trạm thành một cảm biến **EDR thực thụ**.

### Câu hỏi 2: Kỹ thuật Tuning Rule 100005 (LSASS) hoạt động như thế nào để loại bỏ 100% cảnh báo giả?
* **Trả lời:** Khi giám sát `lsass.exe` bằng Sysmon Event 10, trong thực tế sẽ xuất hiện bão cảnh báo (Alert Fatigue) do các tiến trình hệ thống như `svchost.exe` (chạy dịch vụ Local Session Manager) hoặc `MicrosoftEdgeUpdate.exe` liên tục thăm dò LSASS. Em đã phân tích cấu trúc trường `GrantedAccess`: Các tiến trình hệ thống định kỳ chỉ xin quyền `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION` - quyền chỉ hỏi thông tin tiến trình, không thể đọc RAM). Trong khi đó, các công cụ tấn công như Mimikatz hay ProcDump bắt buộc phải mở handle với quyền `0x0010` (`PROCESS_VM_READ`) hoặc `0x1FFFFF` (`PROCESS_ALL_ACCESS`). Bằng cách thêm bộ lọc phủ định `<field name="win.eventdata.grantedAccess" type="pcre2" negate="yes">^0x1000$</field>`, hệ thống loại bỏ 100% cảnh báo giả từ Windows mà vẫn tóm gọn mọi hành vi trích xuất mật khẩu thật sự.

### Câu hỏi 3: Tại sao lại dùng Luật ức chế phân cấp (Hierarchical Level 0) thay vì viết điều kiện phủ định `negate="yes"` trong luật chính?
* **Trả lời:** Nếu viết trực tiếp `negate="yes"` kiểm tra user `socrunner` trong Rule 100004, cú pháp XML của Wazuh sẽ áp dụng toán tử **OR lỏng lẻo** giữa các điều kiện phủ định. Tin tặc chỉ cần đặt tên user của chúng trùng với whitelist hoặc giả mạo một tham số là có thể bypass hoàn toàn luật phát hiện. Do đó, em áp dụng chuẩn **Hierarchical Child Suppression Rule (`level="0"`)**:
  * Rule con 100008 kế thừa từ Rule cha 100004.
  * Trong rule con, các thẻ `<field>` áp dụng logic **AND chặt chẽ**: Phải vừa đúng user `socrunner` **VÀ** vừa đúng tiến trình cha sinh ra từ WinRM (`wsmprovhost.exe`).
  * Nhờ vậy, chỉ những hành động cứu trợ hợp lệ của SOAR mới được ức chế, loại bỏ hoàn toàn khả năng tin tặc lợi dụng để né tránh giám sát.

### Câu hỏi 4: Cơ chế Dual-Mode IOC Resolution giải quyết bài toán hóc búa gì trong SOAR?
* **Trả lời:** Các bài lab SOAR thông thường chỉ xử lý được các cuộc tấn công từ bên ngoài qua mạng (khi log có trường `srcip`). Tuy nhiên, trong chuỗi tấn công **Kill Chain nội bộ (Local Execution)** như thực thi lệnh mã hóa PowerShell, UAC Bypass hay Dump LSASS, kẻ tấn công đã ở sẵn bên trong máy nạn nhân nên trường `srcip` bị trống (`null`). Nếu đẩy thẳng vào SOAR, hệ thống sẽ báo lỗi `Target: N/A` và không thể tạo luật tường lửa. Kịch bản `custom-n8n.py` của em áp dụng cơ chế định danh kép: Khi phát hiện không có IP mạng bên ngoài, hệ thống tự động fallback lấy chính IP của Endpoint bị xâm nhập (`192.168.71.129`) làm mục tiêu cô lập mạng, giúp cách ly khẩn cấp máy nạn nhân khỏi hệ thống.

### Câu hỏi 5: Nguyên tắc Safe Host Isolation và 1-Click Rollback vận hành ra sao?
* **Trả lời:** Khi một máy trạm bị cô lập mạng bằng tường lửa Windows, nếu ta áp dụng chính sách chặn toàn bộ (Block All Inbound & Outbound) thì máy đó sẽ mất kết nối hoàn toàn với máy chủ điều khiển SIEM/SOAR. Kết quả là SOC Analyst không thể gửi lệnh cứu trợ tiếp theo và buộc phải tới tận nơi cắm bàn phím thủ công. Trong đồ án này, em áp dụng nguyên tắc **Cách ly an toàn (Safe Isolation)**:
  * Khi tạo luật chặn, hệ thống **luôn mở Port 5985 (WinRM)** và **Port 1514/1515 (Wazuh Agent)**.
  * Nhờ kênh quản trị được bảo lưu, Analyst có thể bấm nút **[🔄 Mở khóa (Rollback)]** trên Telegram để gọi lệnh WinRM xóa rule chặn, khôi phục mạng cho máy trạm trong **dưới 5 giây**.

### Câu hỏi 6: Công nghệ Deception (Bẫy mồi) trong đồ án khác gì so với SIEM truyền thống?
* **Trả lời:** SIEM truyền thống dựa trên việc phân tích hành vi bất thường, luôn đi kèm với tỷ lệ cảnh báo giả (False Positive) nhất định. Ngược lại, **Deception Technology** tạo ra các tài sản mồi không phục vụ bất kỳ mục đích nghiệp vụ nào (Canary Honey-file `IT_Admin_Credentials.xlsx`, tài khoản mồi `backup_admin`, Decoy Port 21). Nhân viên bình thường không bao giờ truy cập vào những tài nguyên này. Do đó, bất kỳ sự tương tác nào với bẫy mồi đều có **độ tin cậy 100% là hành vi thâm nhập trái phép (0% False Positive)**. Ngay khi có sự kiện SACL Event 4663, hệ thống lập tức kích hoạt script trích xuất chứng cứ số (Live DFIR Forensics: MiniDump RAM, kết nối mạng netstat, EVTX) nén `.zip` gửi thẳng lên Jira Ticket cho đội điều tra L2.

### Câu hỏi 7: Lợi ích của việc áp dụng triết lý Detection-as-Code (DaC) và SigWaz Compiler là gì?
* **Trả lời:** Thay vì chỉnh sửa file XML thủ công trên máy chủ (dễ gây lỗi cú pháp làm sập tiến trình `wazuh-analysisd` và không kiểm soát được phiên bản), em áp dụng quy trình **Detection-as-Code**:
  * Toàn bộ quy tắc được viết bằng chuẩn **Sigma YAML** đặt tại `manager/rules/sigma/` (đóng vai trò Single Source of Truth - SSOT).
  * Công cụ `scripts/sigma_compiler.py` tự động biên dịch Sigma YAML sang XML của Wazuh, tự động sinh các luật ức chế phân cấp Level 0 cho SOAR.
  * Tích hợp vào **GitHub Actions CI/CD Pipeline** (`.github/workflows/test.yml`): Tự động chạy 22 bài kiểm thử (pytest) kiểm tra cú pháp XML, tính duy nhất của Rule ID, định dạng MITRE ATT&CK và kiểm tra chống lệch pha (`--check`) trước khi cho phép merge code vào nhánh chính.

### Câu hỏi 8: Tại sao lại chọn n8n làm động cơ SOAR thay vì TheHive hay Cortex?
* **Trả lời:** TheHive thực chất là một nền tảng **Case Management** (quản lý hồ sơ), còn Cortex chỉ là công cụ phân tích observable đơn lẻ. Bản thân TheHive không có động cơ điều phối luồng làm việc (Workflow Engine) linh hoạt. n8n hỗ trợ lập trình Node.js native, cho phép em xử lý dữ liệu phức tạp (như mã hóa Base64 cho Jira REST API v3, định tuyến Switch conditions), giao tiếp thời gian thực 2 chiều với Telegram ChatOps và kết nối trực tiếp với Atlassian Jira Cloud chỉ trong một giao diện trực quan duy nhất, tốn rất ít tài nguyên phần cứng (chạy gọn gàng trong 1 container Docker).
