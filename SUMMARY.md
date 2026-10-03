# 📋 ĐÁNH GIÁ TỔNG QUAN VÀ LỘ TRÌNH NÂNG CẤP ĐỒ ÁN WAZUH SOC LAB
> **Định vị mục tiêu:** Chuyển hóa đồ án nghiên cứu học thuật thành **Dự án Portfolio chuẩn Enterprise** giúp ứng viên nổi bật trong mắt nhà tuyển dụng và vượt qua các vòng phỏng vấn kỹ thuật vị trí **SOC Analyst (L1/L2)** hoặc **Detection Engineer**.

---

## 📌 PHẦN 1: ĐÁNH GIÁ HIỆN TRẠNG ĐỒ ÁN (CURRENT STATE AUDIT)

### 1.1. Những điểm sáng nổi bật (Strengths đã làm rất tốt)
Đồ án hiện tại đã vượt xa mức một bài thực hành thông thường của sinh viên nhờ các yếu tố:
1. **Kiến trúc bài bản và đóng gói chuẩn Docker:** Triển khai Wazuh Stack (Manager, Indexer, Dashboard) trên Docker Compose single-node, có tinh chỉnh tham số hệ thống nhân Linux (`vm.max_map_count=262144`), phân vùng đĩa cứng (`resizepart/resize2fs`), và giới hạn log container tránh tràn đĩa.
2. **Endpoint Auditing có chiều sâu:** Không chỉ dùng Windows Event Log thuần túy mà đã tích hợp **Microsoft Sysmon v15.2** với file cấu hình tùy biến (`sysmon-config.xml`), cho phép thu thập telemetry chuyên sâu ở tầng nhân (Process, Network, Registry).
3. **Detection Engineering thực thụ:** Đã tự viết **Custom Decoder** (trích xuất regex URL) và **Custom Rules** (Rule 100001 phát hiện Brute Force, Rule 100002 phát hiện Web LFI/Directory Traversal chống bypass double encoding `%252f`), map chuẩn theo framework **MITRE ATT&CK**.
4. **Phòng thủ chủ động (Active Response):** Không dừng lại ở việc sinh alert thụ động mà đã cấu hình lệnh `netsh.exe` tự động can thiệp Windows Defender Firewall để cô lập IP tấn công theo thời gian thực (timeout 600s).
5. **Tự động hóa kiểm thử hồi quy (Phase 4 - Test Automation):** Xây dựng unit test kiểm tra cú pháp XML (`test_detection_config.py`), kiểm tra sức khỏe cụm 3 VM (`lab_health.py`), và script chạy tấn công tự động + xác thực bằng chứng qua WinRM/SSH (`scenario_rdp_bruteforce.py`, `scenario_lfi_web.py`) mang tư duy **Detection-as-Code** (DevSecOps).
6. **Tích hợp ChatOps & Threat Intelligence thời gian thực (Đã hoàn thành):** Đã kết nối thành công Wazuh Manager với **Telegram Bot** tự động gửi thẻ cảnh báo định dạng HTML phong phú (kèm IP tấn công, mã MITRE ATT&CK, trạng thái tường lửa) và liên kết **VirusTotal API** để tự động đối soát danh tiếng tệp tin độc hại (Rule 87105).
7. **Chuẩn hóa quy trình vận hành SOC (Incident Response Playbooks - Đã hoàn thành):** Xây dựng bộ tài liệu SOP chuẩn theo khung **NIST SP 800-61 Rev. 2** và chu trình **SANS PICERL** tại thư mục `playbooks/` cho cả hai kịch bản RDP Brute Force và Web LFI.

---

### 1.2. Khoảng cách (Gap Analysis) so với thực tế vận hành SOC Doanh nghiệp
Dù nền tảng rất vững, đồ án vẫn còn một số "khoảng trống" khiến nhà tuyển dụng SOC kỳ cựu nhận thấy đây vẫn là một lab đóng hộp:

| Tiêu chí đánh giá | Hiện trạng đồ án | Yêu cầu thực tế tại Enterprise SOC |
| :--- | :--- | :--- |
| **Độ bao phủ phát hiện (MITRE ATT&CK)** | Mới có 2 kịch bản: T1110 (Brute Force) và T1190 (LFI/Traversal). | Cần bao phủ chuỗi tấn công hoàn chỉnh (**Full Kill Chain**): Thực thi mã (T1059), Leo thang đặc quyền (T1548), Trích xuất thông tin xác thực (T1003), Ẩn náu (T1547). |
| **Tận dụng Telemetry của Sysmon** | Đã cài Sysmon nhưng 2 kịch bản hiện tại mới chỉ dùng Windows Security Log (Event 4625) và Apache Log. | Sysmon sinh ra để bắt: Event 1 (Process Create), Event 3 (Network), Event 10 (ProcessAccess - LSASS), Event 11 (FileCreate), Event 13 (Registry). Chưa có kịch bản khai thác các event này. |
| **Tự động hóa phản ứng & Cảnh báo (SOAR/ChatOps)** | **[ĐÃ HOÀN THÀNH ✅]** Triển khai n8n SOAR Engine, tích hợp 2-way Telegram ChatOps với 3 nút bấm tương tác ([🚫 Khóa IP 24h], [⚠️ Báo động giả], [📋 Mở Ticket Jira]), làm giàu AbuseIPDB và tự động hóa Jira Cloud REST API. | SOC hiện đại cần cảnh báo tức thì ra **Telegram/Discord/Slack**, tự động tra cứu danh tiếng mã độc qua **VirusTotal / AbuseIPDB** và tạo ticket. |
| **Quy trình & Tài liệu hóa sự cố (IR Playbook)** | **[ĐÃ HOÀN THÀNH]** Đã xây dựng bộ SOP tại `playbooks/` gồm `README.md`, `SOP-01_RDP_Brute_Force_Response.md`, và `SOP-02_Web_LFI_Mitigation.md` theo khung NIST SP 800-61 / SANS PICERL. | SOC Analyst cần biết quy trình: Phân loại mức độ (Triage) -> Cô lập (Containment) -> Diệt trừ (Eradication) -> Khôi phục (Recovery) -> Viết báo cáo điều tra (Incident Report). |
| **Tối ưu hóa cảnh báo & Giảm nhiễu (Tuning)** | Chưa đề cập đến hiện tượng cảnh báo giả (False Positive) và cách whitelist hành vi quản trị hợp lệ. | Một bài toán nhức nhối trong SOC là **Alert Fatigue** (quá tải cảnh báo). Ứng viên cần chứng minh khả năng tuning rule và exception handling. |
| **Định lượng hiệu quả (Metrics & KPIs)** | Chưa có số liệu thống kê thời gian phát hiện và phản ứng. | Cần đo lường **MTTD** (Mean Time to Detect) và **MTTR** (Mean Time to Respond) trước và sau khi có rule/active response. |

---

## 🎯 PHẦN 2: LỘ TRÌNH NÂNG CẤP ĐỂ TẠO ẤN TƯỢNG VƯỢT TRỘI

Dưới đây là 5 hướng nâng cấp cụ thể, được sắp xếp theo mức độ ưu tiên để đưa vào CV.

```
                     ┌────────────────────────────────────────────────────────────────────────┐
                     │                      LỘ TRÌNH HOÀN THIỆN SOC LAB                       │
                     └───────────────────────────────────┬────────────────────────────────────┘
                                                         │
         ┌───────────────────────┬───────────────────────┼───────────────────────┬───────────────────────┐
         ▼                       ▼                       ▼                       ▼                       ▼
  [Hướng 1: Detection]    [Hướng 2: ChatOps/TI]   [Hướng 3: Quy trình]    [Hướng 4: Tuning]       [Hướng 5: SOAR n8n]
  Mở rộng Sysmon Rules    Telegram & VT API       SOC Playbooks & SOP     Giảm False Positive     Tự động hóa Workflow
  - LOLBAS / PowerShell   (ĐÃ HOÀN THÀNH ✅)      - Chuẩn NIST SP 800-61  - Whitelist Admin IP    (ĐÃ HOÀN THÀNH ✅)
  - LSASS Dumping         - Bắn Alert Telegram    (ĐÃ HOÀN THÀNH ✅)      - Tinh chỉnh Threshold  - n8n + Jira Cloud API
  - Persistence RegKey    - Đối soát VirusTotal   - SOP RDP & Web LFI     - Đo lường MTTD / MTTR  - Interactive ChatOps
```

---

### 🚀 Hướng 1: Mở rộng Kịch bản Detection Engineering với Sysmon & Full Kill Chain (Đã hoàn thành ✅)
Đã hoàn thành việc mở rộng hệ thống sang mô hình **Full Kill Chain Attack & Detection** tận dụng triệt để Telemetry của Microsoft Sysmon v15.2 trên Windows Endpoint, bao phủ trọn vẹn 4 giai đoạn trọng yếu của ma trận MITRE ATT&CK:

#### 1. Chi tiết 4 Giai đoạn & Quy tắc Phát hiện (Custom Rules):
* **Stage 1 - Execution (`T1059.001 - Malicious PowerShell Execution`):**
  - **Hành vi:** Kẻ tấn công thực thi PowerShell với cờ ẩn danh, mã hóa chuỗi lệnh (`-EncodedCommand`, `-w hidden`, `-nop`, `-enc`).
  - **Telemetry:** Sysmon **Event ID 1 (Process Create)** qua Windows EventChannel.
  - **Quy tắc phát hiện:** **Rule 100003** (Base filter Event 1) & **Rule 100004 (Level 12)** quét biểu thức chính quy trường `win.system.message` tìm tham số độc hại.
* **Stage 2 - Privilege Escalation (`T1548.002 - UAC Bypass via Registry Hijacking`):**
  - **Hành vi:** Lạm dụng registry hijacking trên khóa `HKCU\Software\Classes\ms-settings\Shell\Open\command` để leo thang đặc quyền mà không kích hoạt cửa sổ cảnh báo UAC (User Account Control).
  - **Telemetry:** Sysmon **Event ID 12 / 13 (RegistryEvent - CreateKey / SetValue)**.
  - **Quy tắc phát hiện:** **Rule 100007 (Level 12)** bắt chuỗi `ms-settings` từ EventChannel.
* **Stage 3 - Persistence (`T1547.001 - Registry Run Key Persistence`):**
  - **Hành vi:** Thiết lập cơ chế bám trụ (Persistence) bằng cách dùng `reg.exe` đăng ký khóa tự khởi động trong `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
  - **Telemetry:** Sysmon **Event ID 12 / 13 (RegistryEvent)**.
  - **Quy tắc phát hiện:** **Rule 100006 (Level 10)** bắt pattern `CurrentVersion\Run` và `CurrentVersion\RunOnce`.
* **Stage 4 - Credential Access (`T1003.001 - LSASS Memory Access`):**
  - **Hành vi:** Mở handle đọc trộm bộ nhớ tiến trình `lsass.exe` nhằm trích xuất thông tin xác thực (Mimikatz/LSASS Dump simulation).
  - **Telemetry:** Sysmon **Event ID 10 (ProcessAccess)** giám sát các handle truy cập vào `TargetImage: lsass.exe`.
  - **Quy tắc phát hiện:** **Rule 100005 (Level 12)** bắt mọi hành vi mở handle nhắm vào `lsass.exe` từ các tiến trình không phải Defender/System.

#### 2. Công cụ Tự động hóa Kiểm thử & Vận hành (E2E Runner):
* **Script thực thi:** [`tests/e2e/scenario_full_killchain.py`](tests/e2e/scenario_full_killchain.py)
* **Tính năng:**
  - Tự động thiết lập baseline, xóa bỏ artifact rác trước khi tấn công.
  - Tuần tự kích hoạt an toàn cả 4 kỹ thuật trên Windows endpoint qua WinRM.
  - Cơ chế **Dynamic Polling Telemetry** đón bắt và đối soát alert trên Wazuh Manager trong thời gian thực.
  - Tích hợp kiểm tra ChatOps Telegram thông báo tức thì các Rule 100004, 100005, 100006, 100007.
  - Tự động xóa sạch dấu vết (Eradication & Remediation) sau khi kiểm thử kết thúc.
* **Kiểm thử đơn vị:** [`tests/unit/test_detection_config.py`](tests/unit/test_detection_config.py) đạt chuẩn **5/5 Tests PASS (100%)**.

---

### 🤖 Hướng 2: Tự động hóa SOAR, Làm giàu Dữ liệu (Threat Intel) & ChatOps (Đã hoàn thành ✅)
Hệ thống đã được tích hợp ChatOps và Threat Intelligence hoàn chỉnh:

1. **Tích hợp ChatOps cảnh báo thời gian thực về Telegram (Đã hoàn thành):**
   - Đã triển khai script [`integrations/telegram/custom-telegram.py`](integrations/telegram/custom-telegram.py) và wrapper [`integrations/telegram/custom-telegram`](integrations/telegram/custom-telegram) vào thư mục `/var/ossec/integrations/` trên Wazuh Manager container.
   - Hỗ trợ cơ chế tự động fallback SSL (`ssl._create_unverified_context()`) phòng trường hợp chứng chỉ môi trường container bị lỗi.
   - Cấu hình khối `<integration>` trong `ossec.conf` tự động kích hoạt cho các Rule: **100001** (RDP Brute Force), **100002** (Web LFI), và **87105** (VirusTotal Alert).
   - Thẻ cảnh báo định dạng HTML đẹp mắt, trích xuất IP attacker, user mục tiêu, endpoint, thời gian và ánh xạ mã kỹ thuật **MITRE ATT&CK**.
   - Hướng dẫn & minh chứng chi tiết: [`integrations/telegram/README.md`](integrations/telegram/README.md).

2. **Làm giàu dữ liệu tự động với Threat Intelligence (VirusTotal API - Đã hoàn thành):**
   - Cấu hình module `virustotal` trong `ossec.conf` liên kết với phân hệ FIM (`syscheck`).
   - Tự động bóc tách hash SHA256/MD5 của tệp tin mới tạo gửi lên VirusTotal API đối soát với >70 Antivirus Engines.
   - Khi có >= 1 Engine nhận diện độc hại, tự động kích hoạt **Rule ID 87105 (Level 12 - High Severity)**.
   - Đã kiểm chứng thực nghiệm bằng file mẫu mã độc EICAR và chụp ảnh minh chứng trên Dashboard.
   - Hướng dẫn chi tiết: [`integrations/virustotal/README.md`](integrations/virustotal/README.md).

3. **Tích hợp Nền tảng Quản lý Sự cố (TheHive / Shuffle SOAR - Đề xuất tương lai):**
   - Hướng mở rộng tiếp theo: Triển khai Shuffle SOAR để tự động tạo ticket sự cố khi có Alert Level >= 10.

---

### 📑 Hướng 3: Xây dựng Bộ Playbook / SOP Ứng phó Sự cố Chuẩn SOC (Đã hoàn thành ✅)
Đã hoàn thành việc xây dựng bộ tài liệu SOP chuẩn hóa theo chu trình **NIST SP 800-61 Rev. 2 / SANS (PICERL)** (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) tại thư mục [`playbooks/`](playbooks/):

* **[playbooks/README.md](playbooks/README.md):** Tổng quan kiến trúc quy trình vận hành SOC, bảng ma trận phân loại mức độ nghiêm trọng (Triage Matrix), quy định thời gian xử lý sự cố (SLA) và quy trình leo thang (Escalation Path).
* **[SOP-01: RDP Brute Force Response](playbooks/SOP-01_RDP_Brute_Force_Response.md):**
  - **Triage:** Phân biệt lỗi đăng nhập thông thường vs tấn công Password Spraying / Brute Force dồn dập.
  - **Analysis:** Kiểm tra nguy cơ tài khoản bị xâm nhập thành công bằng cách truy vết **Windows Event ID 4624 (Logon Type 10 - RemoteInteractive)**.
  - **Containment:** Đánh giá Active Response và quy trình cô lập thủ công khi firewall gặp lỗi.
  - **Eradication & Recovery:** Khóa tài khoản, reset mật khẩu, thu hồi phiên làm việc.
  - **Hardening:** Kích hoạt Account Lockout Policy (GPO), Network Level Authentication (NLA), đổi cổng RDP mặc định.
* **[SOP-02: Web LFI & Path Traversal Mitigation](playbooks/SOP-02_Web_LFI_Mitigation.md):**
  - Phân tích Apache Access Log + Error Log bóc tách URL payload và mã phản hồi HTTP.
  - Truy vết Web Shell và tiến trình con bất thường bằng **Sysmon Event ID 1 & Event ID 11**.
  - Hướng dẫn vá lỗi code PHP (sử dụng whitelist và hàm `basename()`).
  - Củng cố an ninh Web Server (phân quyền thư mục `htdocs`, cấm thực thi script trong thư mục upload).

---

### 🛡️ Hướng 4: Tinh chỉnh Cảnh báo (Tuning) & Đo lường Chỉ số Hiệu năng SOC
Nhà tuyển dụng rất thích ứng viên hiểu bài toán **False Positive (Báo động giả)**:

1. **Kỹ thuật Whitelist & Tuning Rules:**
   - Trong môi trường thực tế, quản trị viên mạng hoặc phần mềm quét lỗ hổng nội bộ (Nessus, OpenVAS) có thể kích hoạt Rule 100001 hoặc 100002.
   - Thêm vào file `custom-rules/local_rules.xml` một rule cấp thấp (Level 0) để bỏ qua cảnh báo nếu IP nguồn thuộc dải máy quét được cấp phép:
     ```xml
     <rule id="100000" level="0">
       <if_sid>60122</if_sid>
       <srcip>192.168.71.200</srcip> <!-- IP của máy Quản trị hoặc Pentester nội bộ -->
       <description>Bỏ qua log quét RDP từ máy Audit nội bộ</description>
     </rule>
     ```
2. **Đo lường định lượng các chỉ số SOC (Metrics):**
   - **MTTD (Mean Time to Detect):** Thời gian từ khi gói tin tấn công đầu tiên được gửi đến khi Wazuh kích hoạt Alert trên Dashboard (ở lab này: ~1.5 đến 3 giây).
   - **MTTR (Mean Time to Respond):** Thời gian từ khi kích hoạt Alert đến khi tường lửa Windows áp dụng rule chặn IP ngắt hoàn toàn kết nối của kẻ tấn công (ở lab này: ~3 đến 5 giây).
   - Đưa bảng so sánh: **Trước khi có hệ thống** (MTTD: Không xác định / Vài tuần; MTTR: Thủ công) vs **Sau khi có Wazuh + Active Response** (MTTD: <3s; MTTR: <5s; Tự động hóa 100%).

---

### ⚙️ Hướng 5: Tự động hóa Điều phối An ninh mạng với n8n & Jira Cloud (SecOps & SOAR Workflow Automation - Đã hoàn thành ✅)
Đã triển khai hoàn chỉnh hệ thống **SOAR / SecOps Workflow Automation** độc lập kết hợp giữa **Wazuh SIEM Manager**, **n8n Automation Engine**, **AbuseIPDB Threat Intelligence**, **Telegram Human-in-the-Loop ChatOps**, và **Jira Cloud REST API v3**:

1. **Hạ tầng SOAR n8n Engine độc lập:**
   - Triển khai n8n Engine trên Docker container (`n8n-soar-engine`) tại cổng `5678` trên máy chủ `wazuh-vm` (`192.168.71.128:5678`).
   - Cấu hình `<integration>` `custom-n8n` trên Wazuh Manager chuyển tiếp thời gian thực các cảnh báo Rule mức cao (`100001`, `100002`, `100004`, `100005`, `100006`, `100007`, `87105`) qua Webhook endpoint `/webhook/wazuh-alert`.
   - Script chuẩn hóa dữ liệu [`integrations/n8n/custom-n8n.py`](integrations/n8n/custom-n8n.py) bóc tách toàn vẹn IOC (IP, User, Command Line, Registry Key) trước khi dispatch vào pipeline.

2. **Bộ 3 Workflows Tự động hóa Chuyên sâu (`integrations/n8n/workflows/`):**
   - **Workflow 1 (`01_wazuh_soar_threat_enrichment.json`):**
     - Tiếp nhận cảnh báo từ Wazuh Webhook.
     - Tự động phân loại Public IP vs Private/RFC1918 IP.
     - Tự động tra cứu điểm uy tín và báo cáo vi phạm qua **AbuseIPDB Cloud API v2**.
     - Gửi Card cảnh báo giàu ngữ cảnh HTML về Telegram kèm **3 nút bấm phản ứng tương tác (Inline Buttons)**.
   - **Workflow 2 (`02_containment_action_executor.json`):**
     - Tiếp nhận callback tương tác từ Telegram Bot (`telegram-callback`).
     - **`[🚫 Khóa IP 24h]`**: Tự động kích hoạt cơ chế cô lập mạng qua Windows Defender Firewall (`New-NetFirewallRule`) và gửi phản hồi xác nhận.
     - **`[⚠️ Bỏ qua / Báo động giả]`**: Ghi nhận log phân loại False Positive vào SOAR Audit Trail, giảm thiểu Alert Fatigue.
     - **`[📋 Mở Ticket Jira]`**: Tự động kết nối **Jira Cloud REST API v3** (`POST /rest/api/3/issue`), khởi tạo Incident Ticket trong Project `SEC` kèm đầy đủ artifacts và trả link ticket trực tiếp về Telegram cho Analyst L2.
   - **Workflow 3 (`03_scheduled_healthcheck_cron.json`):**
     - Thiết lập Cron Trigger định kỳ mỗi 6 giờ tự động kiểm tra sức khỏe của các container Docker, Wazuh Manager, Agent 001, và n8n Engine, sau đó gửi báo cáo tóm tắt về nhóm Telegram.

3. **Tài liệu & Kịch bản Kiểm thử Tự động:**
   - **Playbook ứng phó sự cố SOAR:** [`playbooks/SOP-03_SOAR_Automated_Containment.md`](playbooks/SOP-03_SOAR_Automated_Containment.md).
   - **Tài liệu hướng dẫn n8n & Jira:** [`integrations/n8n/README.md`](integrations/n8n/README.md).
   - **Báo cáo chi tiết Phase 5:** [`reports/Phase-5/Phase-5_SOAR-Workflow-Automation.md`](reports/Phase-5/Phase-5_SOAR-Workflow-Automation.md).
   - **Test Runner E2E tự động:** [`tests/e2e/test_soar_webhook.py`](tests/e2e/test_soar_webhook.py) đạt chuẩn **PASS 100%**.

---

## 💼 PHẦN 3: CHIẾN LƯỢC ĐƯA VÀO CV VÀ CHINH PHỤC PHỎNG VẤN SOC

### 3.1. Cách viết mục Dự án vào CV (Chuẩn format Google XYZ / STAR)

#### ❌ Cách viết thông thường (Yếu, thiếu số liệu, không gây ấn tượng):
> *Dự án: Lab SOC Wazuh*
> * *Cài đặt Wazuh SIEM trên Ubuntu và cài Agent trên Windows 10.*
> * *Mô phỏng tấn công Brute Force bằng Kali Linux.*
> * *Viết luật phát hiện tấn công và cấu hình chặn IP.*

#### ✅ Cách viết chuyên nghiệp cho CV SOC Analyst / Detection Engineer (Mạnh mẽ, giàu từ khóa ATS):

```markdown
### HỆ THỐNG GIÁM SÁT AN NINH MẠNG TẬP TRUNG & TỰ ĐỘNG PHẢN ỨNG SỰ CỐ (WAZUH SIEM/XDR LAB)
**Vai trò:** Detection Engineer & SOC Analyst | **Công nghệ:** Wazuh SIEM/XDR, Docker, Microsoft Sysmon, Python, MITRE ATT&CK, Active Response, WinRM.
* **Thiết kế & Triển khai:** Xây dựng hạ tầng SIEM/XDR tập trung trên nền tảng Docker với cấu hình Kernel Hardening và mở rộng phân vùng lưu trữ, kết nối giám sát Endpoint Windows 10 thông qua kênh giao tiếp mã hóa TLS.
* **Tối ưu hóa Telemetry Endpoint:** Triển khai Microsoft Sysmon v15.2 tùy biến nhằm kiểm toán hành vi chuyên sâu ở tầng nhân hệ điều hành (Kernel-level events: Process Creation, Network Connections, Handle Access).
* **Kỹ nghệ Phát hiện (Detection Engineering):** Thiết kế Custom Decoders (Regex) và Rules tương quan (Correlation Rules) chuẩn hóa theo framework MITRE ATT&CK, phát hiện thành công các kỹ thuật tấn công RDP Brute Force (T1110) và Web Application LFI/Directory Traversal chống bypass double encoding (T1190).
* **Tự động hóa Ứng phó (Active Response):** Thiết lập cơ chế cô lập mối đe dọa thời gian thực, tự động kích hoạt Windows Defender Firewall (`netsh`) ngăn chặn IP kẻ tấn công, giảm thời gian phản ứng (MTTR) từ xử lý thủ công xuống dưới 5 giây.
* **Tích hợp ChatOps & Threat Intelligence:** Kết nối hệ thống với Telegram Bot để tự động đẩy cảnh báo tức thì định dạng HTML phong phú (IP tấn công, tài khoản đích, mã MITRE, trạng thái tường lửa), đồng thời tích hợp VirusTotal REST API tự động tra cứu danh tiếng mã độc qua phân hệ FIM (Rule 87105).
* **Quy trình Vận hành Chuẩn SOC (SOP / Playbooks):** Xây dựng bộ quy trình chuẩn ứng phó sự cố theo khuyến nghị NIST SP 800-61 Rev. 2 / SANS PICERL cho cả hai kịch bản RDP Brute Force và Web LFI, từ khâu Triage đến Hardening hậu sự cố.
* **Quy trình Detection-as-Code & Tự động hóa Kiểm thử:** Xây dựng bộ công cụ Regression Testing độc lập bằng Python (WinRM, SSH, Unittest) tự động hóa quy trình kiểm thử sức khỏe cụm máy chủ và xác thực chuỗi phát hiện - cô lập từ xa, đảm bảo tính ổn định của hệ sinh thái luật.
```

---

### 3.2. Bộ Từ khóa Vàng (Keywords) tối ưu cho bộ lọc tự động ATS
Đảm bảo các thuật ngữ này xuất hiện rải rác trong CV và hồ sơ LinkedIn:
- `SIEM/XDR Architecture`, `Wazuh`, `Sysmon Telemetry`, `Detection Engineering`, `MITRE ATT&CK Mapping`
- `Incident Response (NIST/SANS)`, `Active Response / Automated Containment`, `SOAR`, `ChatOps`
- `Log Analysis & Parsing`, `Custom Decoders & Rules`, `False Positive Tuning`, `Detection-as-Code`
- `Endpoint Detection & Response (EDR)`, `Threat Hunting`, `MTTD / MTTR Optimization`

---

### 3.3. Bộ câu hỏi phỏng vấn thực tế nhà tuyển dụng sẽ hỏi & Chiến lược trả lời

#### Câu 1: "Tại sao bạn lại cần cài thêm Sysmon trong khi Windows đã có sẵn Windows Security Event Logs?"
* **Câu trả lời chuẩn:**
  > "Dạ, Windows Security Event Logs mặc định (như Event ID 4624/4625/4688) rất quan trọng cho kiểm toán xác thực, nhưng có nhiều hạn chế trong việc giám sát hành vi mã độc chuyên sâu. Ví dụ, Event 4688 mặc định không ghi lại đầy đủ đối số dòng lệnh (Command Line Arguments), không ghi nhận chuỗi băm (Hash SHA256) của file thực thi, và không giám sát được các kỹ thuật phức tạp như Process Injection, Process Access vào bộ nhớ LSASS, hay sự thay đổi của Driver. 
  > Sysmon v15.2 hoạt động như một device driver tầng nhân (Kernel-mode), cung cấp các telemetry vô cùng giá trị như Event ID 1 (Process Create kèm Parent-Child tree và Hash), Event ID 3 (Network Connection gắn trực tiếp với Process ID), Event ID 10 (ProcessAccess - cực kỳ hiệu quả để bắt Mimikatz trích xuất bộ nhớ LSASS) và Event ID 13 (Registry modification). Việc kết hợp cả hai giúp Wazuh có bức tranh toàn cảnh mà kẻ tấn công khó có thể lẩn tránh."

#### Câu 2: "Trong Kịch bản 1, bạn cấu hình Active Response chặn IP bằng Firewall trong 600 giây. Tại sao lại là 600 giây mà không chặn vĩnh viễn? Điều gì xảy ra nếu kẻ tấn công giả mạo (Spoof) IP của Gateway hoặc DNS Server nội bộ?"
* **Câu trả lời chuẩn (Thể hiện tư duy vận hành thực tế):**
  > "Dạ, việc thiết lập timeout 600 giây (10 phút) là một thực hành cân bằng rủi ro chuẩn trong SOC:
  > 1. Nó đủ lâu để bẻ gãy đợt tấn công Brute Force tự động của tin tặc và buộc công cụ quét của họ rơi vào trạng thái timeout, trong khi SOC Analyst có thời gian vào điều tra.
  > 2. Chặn tạm thời giúp phòng tránh nguy cơ từ chối dịch vụ tự hủy (Self-DoS). Nếu kẻ tấn công giả mạo IP nguồn của các dịch vụ thiết yếu như Active Directory Domain Controller, Default Gateway, hoặc máy chủ DNS nội bộ, việc chặn vĩnh viễn sẽ làm tê liệt toàn bộ hạ tầng mạng.
  > Trong môi trường sản xuất lớn, chúng ta cần cấu hình Whitelist danh sách các IP hạ tầng quan trọng vào rule Active Response, đồng thời kích hoạt cảnh báo gửi ticket cho SOC Analyst xác minh trước khi thực hiện cô lập vĩnh viễn hoặc cách ly mức Endpoint (Host Isolation)."

#### Câu 3: "Làm thế nào bạn biết một cảnh báo Brute Force là tấn công thật sự hay chỉ là nhân viên gõ sai mật khẩu hoặc một script tự động của IT bị lỗi pass cũ?"
* **Câu trả lời chuẩn (Thể hiện kỹ năng Triage L1/L2):**
  > "Dạ, khi tiếp nhận cảnh báo Event 4625, em sẽ tiến hành quy trình phân loại (Triage) dựa trên các chỉ số:
  > 1. **Tần suất và Tốc độ (Velocity):** Người dùng gõ sai thường chỉ phát sinh 3-5 lần sai trong 1-2 phút. Tấn công tự động (Hydra, xfreerdp) sẽ phát sinh hàng chục đến hàng trăm request chỉ trong vài giây.
  > 2. **Danh sách Username nhắm tới:** Người dùng thật chỉ đăng nhập sai 1 tài khoản của chính họ. Tấn công dò mật khẩu thường thử các tài khoản mặc định (`admin`, `administrator`, `root`, `guest`, `test`) hoặc dùng danh sách từ điển nhiều username khác nhau.
  > 3. **IP nguồn và Workstation Name:** Nếu IP nguồn đến từ dải mạng Public bên ngoài hoặc dải IP lạ, nguy cơ rất cao. Nếu đến từ IP nội bộ của phòng IT hoặc máy của một nhân viên cụ thể, em sẽ kiểm tra xem máy đó có cài task tự động (Scheduled Task/Mapped Drive) đang lưu cache mật khẩu cũ hay không.
  > 4. **Trạng thái Logon Type:** Logon Type 2 (Interactive - ngồi tại máy), Type 3 (Network - SMB), hay Type 10 (RemoteInteractive - RDP) giúp khoanh vùng chính xác vector tiếp cận."

#### Câu 4: "Bạn có thể giải thích ý nghĩa của Phase 4 trong đồ án? Tại sao lại cần viết automation test trong khi hệ sinh thái Wazuh đã có giao diện web để theo dõi?"
* **Câu trả lời chuẩn (Tạo sự khác biệt cực lớn):**
  > "Dạ, Phase 4 giải quyết bài toán cốt lõi của **Detection-as-Code** trong môi trường Agile/DevSecOps:
  > Trong thực tế, khi đội ngũ SOC cập nhật bộ luật mới, nâng cấp phiên bản Wazuh, hoặc thay đổi chính sách thu thập log của Sysmon, rất dễ xảy ra hiện tượng **Hồi quy (Regression)** — tức là một thay đổi mới vô tình làm hỏng các luật phát hiện cũ mà không ai hay biết cho đến khi sự cố thực sự xảy ra.
  > Thay vì phải bật máy ảo, gõ lệnh thủ công và nhìn màn hình bằng mắt để kiểm tra lại hệ thống sau mỗi lần update, em xây dựng bộ script Python kiểm thử tự động 3 bước:
  > - Kiểm tra tĩnh (Static linting) cấu trúc XML của Rule và Decoder.
  > - Kiểm tra động (Health check) trạng thái hoạt động của toàn bộ hạ tầng đa nền tảng (Linux SSH, Windows WinRM, Docker containers, Indexer cluster).
  > - Tự động phát động kịch bản tấn công có kiểm soát và xác thực bằng chứng đa điểm (Windows Event Viewer, Log Active Response, Alert JSON trên Manager) để xuất ra kết quả PASS/FAIL độc lập. Quy trình này giúp bộ luật phát hiện luôn được kiểm chứng liên tục và có thể tích hợp thẳng vào CI/CD pipeline."

---

## 📅 PHẦN 4: CHECKLIST HÀNH ĐỘNG NÂNG CẤP (ACTION PLAN)

Dưới đây là các đầu việc bạn có thể thực hiện theo từng tuần để hoàn thiện đồ án:

### Giai đoạn 1: Quick Wins (Đã hoàn thành 100% ✅)
- [x] Bổ sung thư mục `playbooks/` chứa bộ tài liệu quy trình chuẩn: `playbooks/README.md`, `SOP-01_RDP_Brute_Force_Response.md`, và `SOP-02_Web_LFI_Mitigation.md` (theo chuẩn NIST SP 800-61 / SANS PICERL).
- [x] Bổ sung **Threat Intelligence Integration (VirusTotal API)** cho Wazuh Manager: Cấu hình `ossec.conf` và kiểm chứng với file mẫu EICAR (Rule 87105 Level 12).
- [x] Triển khai **Telegram ChatOps**: Viết `integrations/telegram/custom-telegram.py` (hỗ trợ SSL fallback), cấu hình `<integration>` trong `ossec.conf`, kiểm thử bắn cảnh báo thật tự động qua Rule 100001, 100002, 87105.

### Giai đoạn 2: Mở rộng Kịch bản (3-5 ngày)
- [ ] Triển khai **Kịch bản 3**: Bắt hành vi thực thi mã độc qua PowerShell / LOLBAS (`certutil` download payload) sử dụng telemetry của **Sysmon Event ID 1**. Viết rule `100003` và bổ sung test case tương ứng.
- [ ] Triển khai **Kịch bản 4**: Bắt hành vi dump bộ nhớ `lsass.exe` bằng Sysmon **Event ID 10**. Viết rule `100004`.
- [ ] Cập nhật file `tests/test_detection_config.py` để bổ sung unit test cho rule `100003` và `100004`.

### Giai đoạn 3: Đóng gói Portfolio & Chuẩn bị Phỏng vấn (1-2 ngày)
- [ ] Tạo file sơ đồ tổng thể hệ thống (Architecture Diagram) bao gồm cả luồng Active Response, ChatOps, và Threat Intel.
- [ ] Cập nhật lại file `README.md` chính để liên kết đến file `SUMMARY.md` và các Playbook mới.
- [ ] Chuẩn bị một đoạn video ngắn 2-3 phút hoặc file GIF quay lại cảnh: Tấn công từ Kali -> Alert nhảy trên Telegram/Dashboard -> Firewall tự động chặn IP -> Chạy test automation báo PASS. Đưa link video vào CV/README.

---
*Tài liệu này được biên soạn nhằm chuẩn hóa toàn diện đồ án theo tiêu chuẩn vận hành thực tế của một Trung tâm Điều hành An ninh mạng (Enterprise SOC).*
