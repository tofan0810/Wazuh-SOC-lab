# 📘 SỔ TAY HỌC TẬP & BẢN ĐẶC TẢ KỸ THUẬT PHÒNG LAB WAZUH SOC & SOAR
> **Tài liệu học tập có tính hệ thống (Systematic Study Handbook & Architecture Notes)**  
> **Mục tiêu:** Dùng để ghi chép vào vở, ôn tập kiến trúc, hiểu rõ bản chất từng dòng code/config và tự tin trả lời vấn đáp đồ án tốt nghiệp / phỏng vấn SOC Engineer.

---

# 1. TỔNG QUAN KIẾN TRÚC SOC

### 1.1. Mục tiêu đồ án
Xây dựng một mô hình **Trung tâm Giám sát và Điều hành An ninh mạng (Security Operations Center - SOC)** thu nhỏ nhưng mang đầy đủ năng lực thực chiến cấp doanh nghiệp:
1. **Thu thập dữ liệu đo kiểm (Telemetry Collection):** Bắt trọn hành vi máy trạm từ tầng Kernel (Sysmon) và dịch vụ mạng (Web Apache, RDP).
2. **Phát hiện mối đe dọa (Detection Engineering):** Viết luật tùy biến đối khớp với ma trận **MITRE ATT&CK**.
3. **Làm giàu thông tin (Threat Intelligence Enrichment):** Tự động truy vấn danh tiếng IP/File độc hại qua AbuseIPDB và VirusTotal.
4. **Tự động hóa phản ứng (SOAR & ChatOps 2 chiều):** Điều phối xử lý sự cố với sự tham gia của con người (**Human-in-the-Loop**) qua Telegram Bot và quản lý hồ sơ sự cố trên **Atlassian Jira Cloud**.
5. **Kiểm thử tự động (Detection-as-Code):** Kiểm định độ tin cậy của luật phát hiện bằng kịch bản Python E2E.

### 1.2. Bài toán SOC mà đồ án giải quyết
Trong một SOC truyền thống, trực ca L1/L2 gặp 3 "nút thắt cổ chai" lớn:
* **Alert Fatigue (Kiệt sức vì cảnh báo giả):** Hàng ngàn log sinh ra mỗi ngày, thiếu bộ lọc khiến cảnh báo quan trọng bị trôi.
* **Thời gian phản ứng chậm (High MTTA/MTTR):** Khi có cảnh báo, Analyst phải tra cứu IP thủ công trên trình duyệt, gõ lệnh cấu hình Firewall bằng tay, mở Jira gõ từng trường thông tin $\rightarrow$ Mất 20 – 45 phút, mã độc đã kịp lây lan.
* **Sai sót thao tác (Human Error):** Gõ nhầm cú pháp chặn Firewall hoặc cấu hình sai IP dẫn tới chặn nhầm máy chủ nghiệp vụ.

$\Rightarrow$ **Giải pháp của đồ án:** Tự động hóa toàn bộ khâu điều tra sơ bộ (Triage), làm giàu dữ liệu (Enrichment), cung cấp nút bấm phản ứng 1-chạm (ChatOps Containment) và tự động tạo ticket Jira chuẩn hóa trong **dưới 20 giây**.

---

### 1.3. Kiến trúc Tổng thể & Các Thành phần Chính

```text
========================================================================================
                                 SƠ ĐỒ LUỒNG DỮ LIỆU END-TO-END
========================================================================================

  [ KALI LINUX - 192.168.71.130 ] 
      │ (Attacker giả lập: RDP Brute Force, Web LFI, PowerShell Obfuscation, UAC Bypass)
      ▼
  [ WINDOWS 10 ENDPOINT - 192.168.71.129 ]
      │ • Sysmon v15.2 (Process creation, LSASS memory access, Registry run keys)
      │ • Windows Security Event Log (Event ID 4625 - Failed Logons)
      │ • Apache Access Logs (access.log)
      │ • Wazuh Agent v4.14.5 (Thu thập log & thực thi Active Response qua WinRM)
      │
      │ (Giao thức Wazuh Agent: 1514/TCP mã hóa AES)
      ▼
  [ WAZUH SIEM MANAGER - 192.168.71.128 (Docker) ]
      │ • Analysisd Engine: Giải mã (local_decoder.xml) & Đối khớp luật (local_rules.xml)
      │ • Remoted / Authd / Execd / Integratord Daemon
      │ • alerts.json: Nơi ghi nhận cảnh báo đã kích hoạt
      │
      ├───────────────────────────────┬───────────────────────────────┐
      │ (OpenSearch Port 9200)        │ (<integration> ossec.conf)    │ (<integration> ossec.conf)
      ▼                               ▼                               ▼
  [ Wazuh Indexer & Dashboard ]   [ VirusTotal Cloud API ]     [ custom-n8n.py Dispatcher ]
    (Trực quan hóa SIEM 443)        (Tra cứu Hash file lạ)       (Dual-Mode IOC Resolution)
                                                                      │
                                                                      │ (HTTP POST Webhook JSON)
                                                                      ▼
                                                       [ n8n SOAR ENGINE - Port 5678 ]
                                                           │ (Workflow 1: Threat Enrichment)
                                                           ├─► AbuseIPDB API (Tra cứu IP)
                                                           ├─► Format HTML Alert Card
                                                           ▼
                                                       [ TELEGRAM CHATOPS BOT ]
                                                           │ (@my_wazuh_soc_alert_bot)
                                                           │ Gửi thẻ tương tác kèm 3 nút bấm:
                                                           │ [🚫 Khóa IP 24h] [⚠️ Cảnh báo giả] [📋 Mở Jira]
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
                           [ Nhánh action:block ]  [ Nhánh action:ignore]  [ Nhánh action:jira ]
                                    │                      │                      │
                             Chạy WinRM sang        Ghi SOAR Audit Trail    Gọi Jira Cloud API
                             Windows 10 tạo         bỏ qua báo động         (POST /rest/api/3/issue)
                             Firewall DROP Rule                             Tạo Ticket Project KAN
                                    │                      │                      │
                                    └──────────────────────┴──────────────────────┘
                                                           │
                                                           ▼
                                              Phản hồi kết quả về Telegram
```

---

# 2. LÝ THUYẾT NỀN TẢNG (CHẮT LỌC THỰC CHIẾN)

### 2.1. Telemetry (Dữ liệu Đo kiểm An ninh)
* **Trực giác:** Camera giám sát hành vi của hệ điều hành. Nếu không có camera góc rộng, trộm vào nhà sẽ không để lại dấu vết.
* **Thuật ngữ:** Dữ liệu nhật ký có cấu trúc được sinh ra từ các cảm biến ở tầng nhân (Kernel) và ứng dụng, mô tả: Ai làm? Làm gì? Lúc nào? Trên đối tượng nào?
* **Cơ chế:** Sysmon chèn trình điều khiển lọc (Filter Driver) `SysmonDrv.sys` vào nhân Windows để chặn bắt sự kiện trước khi tiến trình kịp xóa dấu vết.
* **Ví dụ:** Tin tặc gõ `whoami` $\rightarrow$ Sysmon Event 1 bắt trọn `Image: C:\Windows\System32\whoami.exe`, `ParentImage: cmd.exe`, `User: NT AUTHORITY\SYSTEM`.
* **Vị trí trong dự án:** File cấu hình [`deployment/sysmon-config.xml`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/deployment/sysmon-config.xml) nạp trên Windows 10.

### 2.2. Decoders & Rules (Bộ Giải Mã và Luật Đối Khớp)
* **Trực giác:** Decoder là người dịch thuật (biến một đoạn văn lộn xộn thành các ô dữ liệu có nhãn). Rule là quan tòa (so sánh các ô dữ liệu đó với bộ luật để tuyên án).
* **Thuật ngữ:**
  * **Decoder (Regex Parser):** Trích xuất chuỗi log thô thành các trường chuẩn: `srcip`, `url`, `action`, `user`.
  * **Rule (Correlation Logic):** Điều kiện logic (`if-then`) dựa trên `rule_id`, mức độ nghiêm trọng `level`, số lần lặp lại `frequency`, khoảng thời gian `timeframe`.
* **Cơ chế:** Wazuh nhận dòng log $\rightarrow$ đi qua cây Decoders (Parent $\rightarrow$ Child) $\rightarrow$ đẩy sang cây Rules (Level 0 $\rightarrow$ 16).
* **Ví dụ:** Log Apache `192.168.71.130 - - [GET /index.php?page=../../win.ini]` $\rightarrow$ Decoder trích `srcip=192.168.71.130`, `url=../../win.ini` $\rightarrow$ Rule 87105 đối khớp regex `\.\./` $\rightarrow$ Báo động Level 10.
* **Vị trí trong dự án:** [`custom-rules/local_decoder.xml`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/custom-rules/local_decoder.xml) và [`custom-rules/local_rules.xml`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/custom-rules/local_rules.xml).

### 2.3. Active Response (Phòng Thủ Chủ Động)
* **Trực giác:** Phanh tự động trên ô tô khi cảm biến phát hiện vật cản phía trước mà tài xế chưa kịp đạp chân ga.
* **Thuật ngữ:** Khả năng của SIEM/EDR tự động kích hoạt một kịch bản lệnh trên Endpoint để ngăn chặn cuộc tấn công ngay khi Rule tương ứng bị kích hoạt.
* **Cơ chế:** Wazuh Manager gửi thông điệp điều khiển xuống tiến trình `wazuh-execd` của Agent $\rightarrow$ Agent gọi script cục bộ (ví dụ: lệnh `netsh` hoặc PowerShell).
* **Ví dụ:** Rule 100002 phát hiện dò pass RDP 8 lần $\rightarrow$ Wazuh Active Response tự động ra lệnh khóa IP Kali trên Firewall Windows trong 300 giây.
* **Vị trí trong dự án:** Cấu hình `<active-response>` trong [`deployment/ossec.conf`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/deployment/ossec.conf).

### 2.4. SOAR & Human-in-the-Loop ChatOps
* **Trực giác:** Không để hệ thống tự tiện bắn tên lửa, mà hệ thống tự nạp đạn, ngắm bắn, rồi hỏi chỉ huy: *"Bắn hay không?"* Chỉ huy bấm nút trên điện thoại thì mới khai hỏa.
* **Thuật ngữ:**
  * **SOAR (Security Orchestration, Automation, and Response):** Động cơ kết nối các công cụ an ninh rời rạc (SIEM, Threat Intel, Firewall, Jira) thành một quy trình tự động.
  * **Human-in-the-Loop (HITL):** Đưa con người vào vị trí phê duyệt nút thắt, tránh việc tự động hóa khóa nhầm IP máy chủ nghiệp vụ quan trọng.
* **Cơ chế:** n8n đóng vai trò điều phối $\rightarrow$ Đẩy thẻ tin nhắn có nút bấm Inline Keyboard về Telegram $\rightarrow$ Analyst bấm nút $\rightarrow$ Long-polling Bridge bắt Callback ID $\rightarrow$ n8n thực thi hành động đã chọn.
* **Vị trí trong dự án:** Thư mục [`integrations/n8n/`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/integrations/n8n/).

### 2.5. Dual-Mode IOC Resolution (Cơ chế Định danh IOC Kép)
* **Trực giác:** Bị bắn từ xa thì tìm kẻ bắn; tự mình phát bệnh từ bên trong thì cách ly chính mình.
* **Thuật ngữ:** Kỹ thuật chuẩn hóa dữ liệu cảnh báo trong script tích hợp SOAR do dự án tự thiết kế:
  * **Mode 1 (Network Attack):** Khi sự cố có IP nguồn tấn công từ xa (`src_ip` hợp lệ từ Kali `192.168.71.130`) $\rightarrow$ Chọn mục tiêu cô lập là `192.168.71.130`.
  * **Mode 2 (Host-Internal / Kill Chain Attack):** Khi tin tặc đã vào trong máy và chạy mã độc cục bộ (UAC Bypass, Dump LSASS, PowerShell Obfuscation) $\rightarrow$ Cảnh báo không có `srcip` $\rightarrow$ Hệ thống tự động chuyển đổi, chọn IP của chính máy trạm bị xâm nhập (`agent_ip: 192.168.71.129`) làm mục tiêu cô lập mạng.
* **Ý nghĩa:** Triệt tiêu hoàn toàn lỗi hiển thị `Target: N/A` thường gặp ở các bài Lab sơ sài, giúp nút bấm chặn Firewall luôn luôn có đối tượng IP chính xác để thực thi.
* **Vị trí trong dự án:** Hàm `extract_ioc_data()` trong file [`integrations/n8n/custom-n8n.py`](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/integrations/n8n/custom-n8n.py).

---

# 3. THÀNH PHẦN & CÔNG CỤ (SYSTEM INVENTORY)

## 1. Wazuh SIEM & XDR (v4.14.5)
* **Purpose:** Máy chủ trung tâm lưu trữ, biên dịch log, tương quan sự kiện và kích hoạt cảnh báo an ninh.
* **Role in SOC:** Trái tim của hệ thống (Detection & Correlation Engine).
* **Input:** Log thô gửi về từ Agent qua cổng 1514/TCP (Sysmon, Security, Web access).
* **Processing:** Khối `wazuh-analysisd` xử lý log qua bộ giải mã và tập luật XML.
* **Output:** Ghi cảnh báo đạt chuẩn vào `/var/ossec/logs/alerts/alerts.json` và phân phối sang Indexer / SOAR.
* **Important config:** `/var/ossec/etc/ossec.conf` và `/var/ossec/etc/rules/local_rules.xml`.
* **Why this tool:** Mã nguồn mở chuẩn Enterprise mạnh mẽ nhất hiện nay, hỗ trợ sẵn tích hợp EDR và Active Response.

## 2. Microsoft Sysmon (System Monitor v15.2)
* **Purpose:** Bộ cảm biến giám sát tiến trình, mạng và bộ nhớ tầng sâu trên máy trạm Windows.
* **Role in SOC:** Cung cấp nguồn Telemetry chất lượng cao nhất cho EDR.
* **Input:** Mọi hành vi hệ điều hành Windows (Process creation, DLL loading, Memory access, Registry changes).
* **Processing:** Bộ lọc XML cấu hình sẵn (`sysmon-config.xml`) quyết định hành vi nào cần ghi lại, hành vi nào bỏ qua.
* **Output:** Windows Event Log tại kênh `Microsoft-Windows-Sysmon/Operational`.
* **Why this tool:** Windows Event Log mặc định không thể bắt được kỹ thuật đọc trộm bộ nhớ LSASS hoặc Registry Run Key tinh vi.

## 3. n8n SOAR Automation Engine (Docker)
* **Purpose:** Nền tảng điều phối luồng làm việc (Workflow Automation) mã nguồn mở bằng giao diện trực quan và code JavaScript.
* **Role in SOC:** Đóng vai trò Bộ não SOAR kết nối Wazuh $\rightarrow$ AbuseIPDB $\rightarrow$ Telegram $\rightarrow$ WinRM $\rightarrow$ Jira Cloud.
* **Input:** Webhook HTTP POST JSON từ Wazuh Manager và Webhook Callback từ Telegram Bridge.
* **Processing:** Chuẩn hóa dữ liệu, gọi REST API bên thứ 3, định tuyến điều kiện (Switch Node), mã hóa Base64 credentials.
* **Output:** Tin nhắn tương tác Telegram, Ticket sự cố trên Jira Cloud, Lệnh cấu hình Firewall qua WinRM.
* **Why this tool:** Nhẹ hơn TheHive/Cortex, cực kỳ linh hoạt, hỗ trợ native Node.js và dễ debug luồng dữ liệu JSON.

## 4. Telegram Bot API & Custom Bridge (`telegram_bridge.py`)
* **Purpose:** Kênh ChatOps di động nhận cảnh báo và gửi lệnh điều khiển 2 chiều.
* **Role in SOC:** Giao diện tương tác tức thì cho SOC Analyst (Human-in-the-Loop).
* **Input:** HTTP callback khi người dùng bấm nút trên điện thoại.
* **Processing:** Daemon `telegram_bridge.py` chạy kỹ thuật Long-Polling trên `wazuh-vm`, chuyển tiếp callback query vào cổng `5678` của container n8n.
* **Output:** Lệnh phản ứng được gửi tới n8n trong mili-giây mà không cần mở cổng NAT ra Internet.
* **Why this tool:** Telegram hỗ trợ Inline Keyboard Callback mạnh mẽ, bảo mật cao và API hoàn toàn miễn phí.

## 5. Atlassian Jira Cloud (REST API v3 - Project `KAN`)
* **Purpose:** Hệ thống quản lý hồ sơ sự cố (Incident Case Management System).
* **Role in SOC:** Quản lý vòng đời sự cố, bàn giao điều tra từ SOC L1 lên SOC L2, phục vụ báo cáo tuân thủ ISO/IEC 27035.
* **Input:** JSON payload tuân thủ cấu trúc Atlassian Document Format (ADF) gửi qua `POST /rest/api/3/issue`.
* **Output:** Mã vé sự cố chuẩn hóa (ví dụ: `KAN-15`) kèm liên kết trực tiếp trên trình duyệt.
* **Why this tool:** Chuẩn mực quản trị dự án và sự cố CNTT được sử dụng rộng rãi nhất tại các doanh nghiệp thực tế.

## 6. AbuseIPDB & VirusTotal Cloud APIs
* **Purpose:** Nền tảng tình báo mối đe dọa (Threat Intelligence Platform).
* **Role in SOC:** Làm giàu ngữ cảnh cảnh báo (Context Enrichment).
* **Input:** Địa chỉ IP nguồn (AbuseIPDB) hoặc mã băm MD5/SHA256 file (VirusTotal).
* **Output:** Tỷ lệ phần trăm độc hại (Abuse Confidence Score), số lượt báo cáo, quốc gia xuất xứ.
* **Why this tool:** Cung cấp thông tin xác thực tức thì để Analyst biết chắc chắn một IP có phải là máy chủ tấn công hay không.

---

# 4. PHÂN TÍCH SOURCE CODE & CONFIGURATION CHI TIẾT

## 4.1. File: `custom-rules/local_rules.xml`

### Mục đích:
Tập hợp toàn bộ các quy tắc phát hiện tùy biến (Custom Detection Rules) của phòng Lab, bao gồm phát hiện dò mật khẩu RDP, khai thác Web LFI, và 4 giai đoạn MITRE ATT&CK Kill Chain.

### Đoạn code quan trọng 1: Phát hiện RDP Brute Force (T1110.001)
```xml
  <!-- Rule 100001: Bắt 1 lần đăng nhập thất bại -->
  <rule id="100001" level="5">
    <if_sid>60122</if_sid>
    <field name="win.system.eventID">^4625$</field>
    <description>Windows: Logon Failure on Target Endpoint</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <!-- Rule 100002: Gom 8 lần thất bại trong 60 giây -> Tuyên án Brute Force -->
  <rule id="100002" level="10" frequency="8" timeframe="60">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip />
    <description>SOC Alert: Multiple RDP Logon Failures Detected (Potential Brute Force Attack)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>
```
* **Giải thích code:**
  * Rule 100001 kế thừa từ rule hệ thống Windows `60122`, lọc đúng Event ID 4625.
  * Rule 100002 sử dụng cơ chế tương quan `frequency="8"` và `timeframe="60"`. Nếu trong 60 giây có 8 sự kiện 100001 sinh ra từ cùng một IP nguồn (`<same_source_ip />`), cảnh báo mức 10 sẽ được kích hoạt.
* **Ý nghĩa:** Tránh báo động giả khi người dùng vô tình gõ sai mật khẩu 1-2 lần; chỉ kích hoạt khi có hành vi dò quét tự động với tần suất cao.

---

### Đoạn code quan trọng 2: Phát hiện Truy cập Bộ nhớ LSASS & Tuning Giảm Báo Động Giả (T1003.001)
```xml
  <!-- Rule 100005: Sysmon Event 10 - Process Access LSASS -->
  <rule id="100005" level="12">
    <if_group>sysmon_event10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
    <!-- TUNING CHỐNG FALSE POSITIVE TỪ SVCHOST VÀ EDGE UPDATE -->
    <field name="win.system.message" type="pcre2" negate="yes">(?i)GrantedAccess:\s*0x1000\b</field>
    <description>MITRE T1003.001: Suspicious Process Accessed LSASS Memory (Potential Mimikatz Credential Dumping)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
```
* **Giải thích code:**
  * Lắng nghe Sysmon Event ID 10 (ProcessAccess), nhắm vào tiến trình đích `lsass.exe` (Local Security Authority Subsystem Service - nơi lưu trữ mật khẩu mã hóa trong RAM).
  * Điểm đắt giá nhất là dòng `negate="yes">(?i)GrantedAccess:\s*0x1000\b`: Trong Windows, các tiến trình hệ thống định kỳ như `svchost.exe` (`lsm.dll`) hoặc `MicrosoftEdgeUpdate.exe` chỉ xin quyền `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION` - quyền chỉ hỏi thông tin tiến trình cơ bản, không thể đọc RAM). Bằng cách phủ định quyền này, hệ thống loại bỏ 100% cảnh báo giả từ Windows nhưng vẫn tóm gọn các công cụ như Mimikatz hay ProcDump vì chúng bắt buộc phải đòi quyền `0x0010` (`PROCESS_VM_READ`) hoặc `0x1FFFFF` (`PROCESS_ALL_ACCESS`).
* **Security Impact:** Bảo vệ khu vực nhạy cảm nhất của Windows, ngăn chặn đánh cắp tài khoản Domain Admin.

---

### Đoạn code quan trọng 3: Phát hiện UAC Bypass qua Fodhelper (T1548.002)
```xml
  <!-- Rule 100007: Sysmon Event 1 - Fodhelper UAC Bypass -->
  <rule id="100007" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)fodhelper\.exe</field>
    <description>MITRE T1548.002: UAC Bypass via Fodhelper Registry Hijack Detected</description>
    <mitre>
      <id>T1548.002</id>
    </mitre>
  </rule>
```
* **Giải thích code:** Bình thường tiến trình quản lý tính năng của Windows `fodhelper.exe` không bao giờ sinh ra tiến trình con là `cmd.exe` hoặc `powershell.exe`. Khi kẻ tấn công chèn lệnh vào registry `ms-settings\Shell\Open\command`, Windows sẽ tự động chạy lệnh đó dưới quyền Admin tối cao mà không bật hộp thoại xác nhận UAC. Rule 100007 bắt sự kiện tạo tiến trình (Event 1) có `parentImage` là `fodhelper.exe`.

---

## 4.2. File: `custom-rules/local_decoder.xml`

### Mục đích:
Bóc tách các dòng log truy cập web thô từ Apache Web Server thành các trường chuẩn để phục vụ viết luật phát hiện tấn công LFI/RFI/SQLi.

```xml
<decoder name="web-access-lfi">
  <parent>windows-date-format</parent>
  <type>windows</type>
  <regex offset="after_parent">^(\S+) \S+ \S+ \[\S+ \S+\] "(\S+) (\S+) \S+" (\d+) \d+</regex>
  <order>srcip, protocol, url, id</order>
</decoder>
```
* **Giải thích code:**
  * Kế thừa từ bộ giải mã cha `windows-date-format`.
  * Đoạn Regex bắt từng phần tử của chuẩn log Common Log Format (NCSA):
    * Nhóm 1 `(\S+)`: Trích xuất địa chỉ IP của Client truy cập $\rightarrow$ gán vào trường `srcip`.
    * Nhóm 2 `(\S+)`: Phương thức HTTP (GET, POST) $\rightarrow$ gán vào `protocol`.
    * Nhóm 3 `(\S+)`: Đường dẫn URL yêu cầu $\rightarrow$ gán vào `url`.
    * Nhóm 4 `(\d+)`: Mã phản hồi HTTP (200, 404, 500) $\rightarrow$ gán vào `id`.
* **Ý nghĩa:** Nhờ bóc tách được trường `url`, Rule 87105 mới có thể kiểm tra xem trong URL có chứa chuỗi duyệt thư mục `../` hoặc `win.ini` hay không.

---

## 4.3. File: `integrations/n8n/custom-n8n.py`

### Mục đích:
Cầu nối trung gian tiếp nhận file JSON cảnh báo tạm thời do Wazuh Manager truyền qua tham số `$1`, thực hiện chuẩn hóa dữ liệu, giải quyết địa chỉ IOC (Dual-Mode Resolution) và bắn HTTP POST vào n8n Webhook.

```python
def extract_ioc_data(alert_data):
    """Cơ chế Dual-Mode IOC Resolution độc quyền của Lab"""
    rule_id = alert_data.get("rule", {}).get("id", "N/A")
    agent_info = alert_data.get("agent", {})
    endpoint_ip = agent_info.get("ip", "192.168.71.129")
    endpoint_name = agent_info.get("name", "windows-victim")

    data = alert_data.get("data", {})
    src_ip = data.get("srcip") or alert_data.get("srcip")

    # MODE 1: Tấn công mạng từ xa có IP rõ ràng (ví dụ: Kali 192.168.71.130)
    if src_ip and src_ip not in ("-", "127.0.0.1", "0.0.0.0", ""):
        target_ioc = src_ip
        is_internal_killchain = False
    else:
        # MODE 2: Tấn công nội bộ chuỗi Kill Chain (Local Execution)
        # Tự động Fallback lấy chính IP của Endpoint bị xâm hại để cô lập máy
        target_ioc = endpoint_ip
        is_internal_killchain = True

    return {
        "rule_id": rule_id,
        "src_ip": target_ioc,           # Luôn đảm bảo có IP thật, không bao giờ N/A
        "endpoint_ip": endpoint_ip,
        "endpoint_name": endpoint_name,
        "is_internal": is_internal_killchain
    }
```
* **Giải thích code:**
  * Hàm kiểm tra `src_ip`. Nếu cuộc tấn công diễn ra từ xa qua mạng (RDP dò mật khẩu hoặc Web LFI), `src_ip` sẽ chứa IP của máy Kali $\rightarrow$ Trả về để n8n gọi lệnh chặn IP đó.
  * Nếu cuộc tấn công xảy ra trực tiếp trên máy nạn nhân (UAC Bypass, Dump LSASS, chạy mã PowerShell), `src_ip` sẽ rỗng. Lúc này script kích hoạt **Mode 2**: Lấy ngay IP của máy nạn nhân `endpoint_ip` (`192.168.71.129`) làm mục tiêu cô lập mạng, ngăn chặn máy nạn nhân giao tiếp với máy chủ C2 của tin tặc.
* **Security Impact:** Đảm bảo hệ sinh thái SOAR luôn vận hành ổn định, loại bỏ hoàn toàn các lỗi runtime do trường dữ liệu bị `null` hoặc `undefined`.

---

## 4.4. File: `integrations/n8n/workflows/02_containment_action_executor.json`

### Mục đích:
Tiếp nhận Callback phản hồi từ nút bấm Telegram, phân tích ý định (`action:block`, `action:ignore`, `action:jira`), thực thi lệnh cách ly Firewall hoặc tạo ticket Jira Cloud REST API v3.

### Đoạn code quan trọng: Node JavaScript tạo Payload và Header xác thực Jira Cloud
```javascript
// Trích xuất thông tin sự cố từ Telegram Callback
const item = $('Parse Callback & Intent').item.json;
const summary = `[Wazuh SOAR Incident] Rule ${item.rule_id} on ${item.target}`;
const desc = `Automated Security Incident Ticket dispatched by Wazuh-n8n DevSecOps Pipeline.\n\n` +
  `• Alert ID: ${item.alert_id}\n` +
  `• Triggered Rule ID: ${item.rule_id}\n` +
  `• Attacker Source / Target: ${item.target}\n` +
  `• Triage Operator: @${item.operator}\n` +
  `• Severity Level: High\n` +
  `• Recommended Action: Immediate Tier-2 SOC Analyst investigation required. Perform host artifact triage, review process tree, examine telemetry logs, and verify containment status.`;

// Tạo Header Basic Authentication an toàn bằng Buffer Node.js
const email = $env.JIRA_EMAIL || 'tn421015@gmail.com';
const token = $env.JIRA_API_TOKEN || '';
const authHeader = 'Basic ' + Buffer.from(email + ':' + token).toString('base64');

return {
  auth_header: authHeader,
  fields: {
    project: { key: $env.JIRA_PROJECT_KEY || 'KAN' },
    summary: summary,
    description: {
      type: 'doc',
      version: 1,
      content: [
        {
          type: 'paragraph',
          content: [{ type: 'text', text: desc }]
        }
      ]
    },
    issuetype: { name: 'Task' },
    priority: { name: 'High' }
  }
};
```
* **Giải thích code:**
  * **Xử lý Basic Auth:** API v3 của Jira Cloud bắt buộc xác thực bằng chuỗi mã hóa Base64 dạng `email:api_token`. Trong n8n, nếu dùng biểu thức `{{ ... }}` bên ngoài HTTP Request node thì đối tượng `Buffer` bị khóa (undefined). Bằng cách xử lý bên trong Code Node, ta tận dụng được `Buffer.from(...).toString('base64')` của Node.js để tạo ra `auth_header` hoàn hảo.
  * **Cấu trúc Atlassian Document Format (ADF):** Trường `description` của Jira Cloud v3 không nhận chuỗi text thuần túy mà yêu cầu cây cấu trúc dạng tài liệu (`type: "doc"`, `type: "paragraph"`). Đoạn code đóng gói dữ liệu chính xác 100% theo chuẩn này, đảm bảo request `POST /rest/api/3/issue` luôn trả về mã HTTP `201 Created`.

---

## 4.5. File: `integrations/n8n/telegram_bridge.py`

### Mục đích:
Cầu nối trung chuyển Callback từ máy chủ Telegram Cloud vào mạng nội bộ riêng tư (Private Lab).

```python
def poll_updates(offset=None):
    """Kỹ thuật Long-Polling: Lắng nghe sự kiện từ Telegram mà không cần mở Port NAT"""
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
* **Giải thích code:** Máy chủ Lab nằm sau dải mạng ảo VMware NAT (`192.168.71.0/24`), không có IP tĩnh công khai (Public IP). Do đó Telegram Webhook không thể đẩy request từ Internet vào máy ảo được. Kịch bản sử dụng vòng lặp **Long-Polling** `getUpdates?timeout=20`: Tiến trình chủ động mở kết nối ra ngoài máy chủ Telegram Cloud và treo đợi 20 giây; ngay khi Analyst bấm nút, máy chủ Telegram sẽ trả về sự kiện lập tức $\rightarrow$ script chuyển tiếp vào n8n webhook cục bộ qua `http://127.0.0.1:5678/webhook/telegram-callback`.
* **Ý nghĩa:** Giải quyết bài toán triển khai ChatOps trong môi trường Lab nội bộ, On-Premise hoặc mạng cô lập (Air-gapped Network) mà không cần dùng phần mềm đục lỗ mạng bên thứ 3 (như ngrok).

---

## 4.6. File: `scripts/sync_env.py` & `sync_env.bat`

### Mục đích:
Bộ công cụ tự động hóa cấu hình và đồng bộ hóa biến môi trường 1-click. Tự động kiểm tra tính hợp lệ của toàn bộ API Cloud và nạp cấu hình an toàn lên máy chủ Wazuh và n8n mà **không làm lộ Secret vào Git**.

```python
def render_ossec_conf(env_vars):
    """Cơ chế Render an toàn: Tạo file cấu hình tạm thời, bảo vệ template gốc khỏi GitGuardian"""
    with open(OSSEC_CONF_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    bot_token = env_vars.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env_vars.get("TELEGRAM_CHAT_ID", "")
    webhook_url = env_vars.get("N8N_WEBHOOK_URL", "")

    # Thay thế token vào nội dung tạm thời
    content = re.sub(r'(<name>custom-telegram</name>\s*<api_key>)[^<]*(</api_key>)', rf'\g<1>{bot_token}\g<2>', content)
    content = re.sub(r'(<name>custom-telegram</name>[\s\S]*?<hook_url>)[^<]*(</hook_url>)', rf'\g<1>{chat_id}\g<2>', content)
    
    # Ghi ra file tạm được GitIgnore bảo vệ (.ossec.conf.rendered)
    with open(RENDERED_OSSEC_CONF, "w", encoding="utf-8") as f:
        f.write(content)
    return True
```
* **Giải thích code:** Thay vì ghi đè trực tiếp token thật vào file `deployment/ossec.conf` (khiến GitGuardian chặn commit hoặc nguy cơ lộ bí mật lên GitHub), script đọc file template gốc, thay thế token vào bộ nhớ rồi ghi ra file tạm `.ossec.conf.rendered`. File tạm này đã được khai báo trong `.gitignore` $\rightarrow$ Script dùng SCP đẩy file tạm lên Wazuh VM $\rightarrow$ File template trong Git luôn giữ nguyên giá trị giả định an toàn `YOUR_TELEGRAM_BOT_TOKEN`.
* **Security Impact:** Đảm bảo tuân thủ tuyệt đối chuẩn DevSecOps: **Zero Secrets in Code Repository**.

---

# 5. SOC DETECTION & MONITORING WORKFLOW

### Quy Trình Xử Lý Sự Kiện Phát Hiện (Event-to-Alert Pipeline):

```text
[ Windows / Web / Endpoint Event ]
                 │
                 ▼ (Log Collector đẩy qua port 1514/TCP)
[ Wazuh Manager: Analysisd Engine ]
                 │
                 ▼
[ Pre-Decoding & Decoding (local_decoder.xml) ]
                 │ Trích xuất: srcip, url, eventID, targetImage, commandLine
                 ▼
[ Rule Evaluation Tree (local_rules.xml) ]
                 │ Kiểm tra điều kiện:
                 │ • Có phải Event 4625 lặp lại 8 lần? (Rule 100002)
                 │ • Có chứa chuỗi "../" trong URL? (Rule 87105)
                 │ • Có mở LSASS với quyền đọc bộ nhớ? (Rule 100005)
                 │ • Có tiến trình con sinh ra từ Fodhelper? (Rule 100007)
                 ▼
[ Alert Generation ]
                 │ Ghi vào /var/ossec/logs/alerts/alerts.json
                 │ Gắn nhãn MITRE ATT&CK ID & Severity Level
                 ▼
[ Integrator Dispatcher ]
                 │ Gọi custom-n8n.py qua tham số dòng lệnh $1
                 ▼
[ SOAR n8n Webhook Pipeline ]
```

### Bảng Ma Trận Quy Tắc Phát Hiện (Detection Rules Matrix):

| Rule ID | Tên Kỹ Thuật MITRE | Nguồn Telemetry Thu Thập | Điều Kiện Kích Hoạt Cảnh Báo | Mức Độ (Level) | Phương Pháp Giảm Báo Động Giả (Tuning) |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **100001** | `T1110.001` (Password Guessing) | Windows Security Event 4625 | Có 1 phiên xác thực RDP thất bại | Level 5 | Chỉ làm rule nền tảng, không kích hoạt alert diện rộng. |
| **100002** | `T1110.001` (RDP Brute Force) | Windows Security Event 4625 | Xuất hiện **8 lần rule 100001 trong 60 giây** từ cùng 1 IP | **Level 10 (High)** | Dùng ngưỡng `frequency="8"` để loại trừ người dùng gõ nhầm pass 1-2 lần. |
| **87105** | `T1190` (Exploit Public Application) | Apache Web `access.log` qua custom decoder | URL chứa `../`, `..\`, `win.ini` hoặc `system.ini` | **Level 10 (High)** | Lọc theo các chuỗi payload khai thác Directory Traversal điển hình. |
| **100004** | `T1059.001` (PowerShell Obfuscation) | Sysmon Event 1 (ProcessCreate) | CommandLine chứa cờ mã hóa: `-enc`, `-encodedcommand` | **Level 8 (Medium)** | Bắt buộc đối soát tiến trình cha và giải mã base64 trước khi phản ứng. |
| **100005** | `T1003.001` (LSASS Credential Dumping) | Sysmon Event 10 (ProcessAccess) | `TargetImage` là `lsass.exe` | **Level 12 (Critical)** | **Phủ định quyền `0x1000`** để loại bỏ 100% nhiễu hệ thống từ `svchost.exe` và `EdgeUpdate`. |
| **100006** | `T1547.001` (Registry Run Keys) | Sysmon Event 12/13 (Registry) | Thao tác ghi khóa vào `CurrentVersion\Run` hoặc `RunOnce` | **Level 8 (Medium)** | Giám sát các tiến trình lạ tự cài đặt cơ chế khởi động cùng Windows. |
| **100007** | `T1548.002` (Bypass UAC via Fodhelper) | Sysmon Event 1 (ProcessCreate) | `ParentImage` là `fodhelper.exe` sinh ra tiến trình con | **Level 12 (Critical)** | Bình thường Fodhelper không bao giờ tạo tiến trình con $\rightarrow$ Tỷ lệ chính xác 100%. |

---

# 6. INCIDENT RESPONSE & SOAR WORKFLOW CHI TIẾT

Toàn bộ quá trình phản ứng tự động hóa được thiết kế theo vòng đời ứng phó sự cố của **NIST SP 800-61 Rev. 2** (Chu trình 4 bước: Preparation $\rightarrow$ Detection & Analysis $\rightarrow$ Containment, Eradication & Recovery $\rightarrow$ Post-Incident Activity):

```text
========================================================================================
                      CHI TIẾT VÒNG ĐỜI SOAR INCIDENT RESPONSE
========================================================================================

1. CẢNH BÁO PHÁT SINH (Detection)
   • Wazuh kích hoạt Rule (ví dụ Rule 100007 - UAC Bypass).
   • wazuh-integratord chuyển alert JSON cho custom-n8n.py.

2. CHUẨN HÓA & LÀM GIÀU DỮ LIỆU (Triage & Enrichment)
   • custom-n8n.py phân tích: Cảnh báo nội bộ -> gán target_ioc = 192.168.71.129.
   • Bắn HTTP POST -> n8n Webhook Ingest (/webhook/wazuh-alert).
   • n8n kiểm tra: Nếu là Public IP -> Gọi AbuseIPDB API lấy Reputation Score.
   • Xây dựng thẻ cảnh báo HTML phong phú (Rich Text) kèm 3 nút bấm tương tác.

3. THÔNG BÁO TỨC THÌ (ChatOps Notification)
   • Gửi tin nhắn Telegram trong < 3 giây tới @my_wazuh_soc_alert_bot.
   • Trực ca SOC nghe tiếng chuông điện thoại, đọc ngay bối cảnh tấn công.

4. PHÊ DUYỆT CỦA CON NGƯỜI (Human-in-the-Loop Decision)
   • Analyst chọn 1 trong 3 nút bấm trên Telegram:
     - [🚫 Khóa IP 24h]    -> Kích hoạt cách ly mạng khẩn cấp.
     - [⚠️ Báo động giả]   -> Đánh dấu sự kiện an toàn, ghi Audit Trail.
     - [📋 Mở Ticket Jira] -> Chuyển vụ việc lên hàng đợi điều tra tầng sâu L2.

5. THI HÀNH PHẢN ỨNG (Containment & Case Management Execution)
   • Nhánh Khóa IP: n8n gọi WinRM PowerShell sang máy Windows 10:
     New-NetFirewallRule -DisplayName "SOAR-BLOCK-192.168.71.129" -Direction Inbound/Outbound -Action Block
   • Nhánh Jira: n8n gửi request POST /rest/api/3/issue sang Atlassian Jira Cloud:
     Tạo Ticket KAN-15 chứa đầy đủ Alert ID, MITRE Tactic, IOC và khuyến nghị L2.
   • Phản hồi tin nhắn xác nhận kèm liên kết trực tiếp về Telegram cho Analyst.
```

---

# 7. HƯỚNG DẪN ÔN TẬP VẤN ĐÁP ĐỒ ÁN (VIVA DEFENSE Q&A)

Dưới đây là 5 câu hỏi trọng điểm giúp bạn tự tin đạt điểm tuyệt đối trước hội đồng:

### Câu hỏi 1: Tại sao hệ thống phải dùng Sysmon kết hợp cùng Wazuh Agent?
* **Trả lời:** Wazuh Agent mặc định chủ yếu thu thập Windows Event Log cơ bản và thông tin hệ thống bề nổi. Các kỹ thuật tấn công hiện đại như **Dump bộ nhớ LSASS (T1003.001)** hoặc **UAC Bypass (T1548.002)** không sinh ra log rõ ràng trong Windows Event Viewer. Sysmon v15.2 hoạt động như một trình điều khiển ở tầng nhân (Device Driver), cung cấp Telemetry chuyên sâu: Event 1 (Dòng lệnh CommandLine đầy đủ và Hash tiến trình), Event 10 (Tiến trình này mở handle truy cập tiến trình khác với quyền gì), Event 12/13 (Thao tác Registry chi tiết). Việc kết hợp này biến máy trạm thành một cảm biến **EDR thực thụ**.

### Câu hỏi 2: Tuning Rule 100005 (LSASS) hoạt động như thế nào để diệt trừ False Positive?
* **Trả lời:** Khi giám sát `lsass.exe` bằng Sysmon Event 10, trong môi trường thực tế sẽ bị bão cảnh báo (Alert Fatigue) bởi các tiến trình Windows lành tính: `svchost.exe` (chạy dịch vụ Local Session Manager `lsm.dll`) và `MicrosoftEdgeUpdate.exe` liên tục thăm dò LSASS. Em đã phân tích sâu cấu trúc của trường `GrantedAccess`: Các tiến trình hệ thống định kỳ chỉ yêu cầu quyền `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION` - quyền chỉ đọc trạng thái tiến trình, không đọc được bộ nhớ). Trong khi đó, các công cụ tấn công như Mimikatz hay ProcDump bắt buộc phải mở handle với quyền `0x0010` (`PROCESS_VM_READ`) hoặc `0x1FFFFF` (`PROCESS_ALL_ACCESS`). Bằng cách thêm bộ lọc `<field name="win.system.message" type="pcre2" negate="yes">(?i)GrantedAccess:\s*0x1000\b</field>`, hệ thống loại bỏ 100% cảnh báo giả từ hệ điều hành nhưng vẫn tóm gọn mọi hành vi trích xuất mật khẩu thật sự.

### Câu hỏi 3: Cơ chế Dual-Mode IOC Resolution giải quyết bài toán gì trong SOAR?
* **Trả lời:** Các bài lab SOAR thông thường chỉ xử lý được các cuộc tấn công từ bên ngoài qua mạng (khi log có trường `srcip`). Tuy nhiên, trong chuỗi tấn công **Kill Chain nội bộ (Local Execution)** như thực thi lệnh mã hóa PowerShell, UAC Bypass hay Dump LSASS, kẻ tấn công đã ở sẵn bên trong máy nạn nhân nên trường `srcip` bị trống (`null`). Nếu đẩy thẳng vào SOAR, hệ thống sẽ báo lỗi `Target: N/A` và không thể tạo luật tường lửa. Kịch bản `custom-n8n.py` của em áp dụng cơ chế định danh kép: Khi phát hiện không có IP mạng bên ngoài, hệ thống tự động fallback lấy chính IP của Endpoint bị xâm nhập (`192.168.71.129`) làm mục tiêu cô lập mạng, giúp cách ly khẩn cấp máy nạn nhân khỏi hệ thống.

### Câu hỏi 4: Tại sao chọn n8n làm SOAR thay vì TheHive hoặc Cortex?
* **Trả lời:** TheHive thực chất là một nền tảng **Case Management** (quản lý hồ sơ), còn Cortex chỉ là một công cụ phân tích observable (Analyzer). Bản thân TheHive không có động cơ điều phối luồng làm việc (Workflow Engine) linh hoạt như n8n. n8n hỗ trợ lập trình Node.js native, cho phép em xử lý dữ liệu phức tạp (như mã hóa Base64 cho Jira REST API v3, định tuyến Switch conditions), giao tiếp thời gian thực 2 chiều với Telegram ChatOps và kết nối trực tiếp với Atlassian Jira Cloud chỉ trong một giao diện duy nhất, tốn rất ít tài nguyên phần cứng (chạy gọn gàng trong 1 container Docker).

### Câu hỏi 5: Lợi ích của việc áp dụng triết lý Detection-as-Code (DaC) trong đồ án là gì?
* **Trả lời:** Em không chỉ viết luật phát hiện rồi để đó, mà quản lý toàn bộ Rules, Decoders và kịch bản tấn công như mã nguồn phần mềm (Code). Em xây dựng các bộ kiểm thử đơn vị (`pytest tests/unit/`) để kiểm tra cú pháp XML, tính duy nhất của Rule ID trước khi triển khai; đồng thời xây dựng các bộ runner kiểm thử toàn trình (`scenario_full_killchain.py`, `scenario_rdp_bruteforce.py`, `scenario_lfi_web.py`) để tự động hóa việc giả lập tấn công từ Kali và xác minh trên SIEM. Điều này giúp đội ngũ an ninh mạng có thể kiểm tra hồi quy (Regression Testing) mỗi khi có bản cập nhật mới mà không sợ làm sập hệ thống giám sát.
