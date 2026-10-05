# 🚀 Kế Hoạch Nâng Cấp & Hoàn Thiện Hệ Thống Wazuh SOC & SOAR Lab
> **Tài liệu Kế hoạch Phát triển Tiếp theo (Next-Step Engineering Roadmap)**  
> **Phiên bản:** 1.0 | **Ngày lập:** Tháng 10/2026 | **Tác giả:** Đội ngũ Kỹ sư Vận hành SOC Lab

---

## 📌 Đánh Giá Hiện Trạng Hệ Thống (Current State Assessment)

Đứng dưới góc nhìn của **Kỹ sư An ninh mạng / Trưởng nhóm SOC (SOC Lead)** và **Hội đồng chấm đồ án tốt nghiệp**, dự án hiện tại đã đạt mức **Rất Tốt (khoảng 8.5 – 9.0/10)** với đầy đủ các thành tố kỹ thuật cốt lõi:
- ✅ **Hạ tầng Lab thực chiến:** 3 máy ảo độc lập (Kali Linux, Windows 10 Endpoint, Ubuntu Wazuh SIEM Docker).
- ✅ **Năng lực giám sát chuyên sâu:** Phối hợp giữa Wazuh Agent 4.14.5 và Microsoft Sysmon v15.2.
- ✅ **Tập luật phát hiện tùy biến (Custom Rules):** RDP Brute Force (Event 4625), Web LFI (Custom Decoder) và chuỗi 4 giai đoạn MITRE ATT&CK Kill Chain (T1059, T1548, T1547, T1003).
- ✅ **Tự động hóa SOAR & ChatOps 2 chiều:** n8n Workflow Engine kết hợp AbuseIPDB, VirusTotal, Telegram Long-Polling Bridge và Atlassian Jira Cloud REST API v3.
- ✅ **Detection-as-Code & Kiểm thử hồi quy:** Bộ Python runner E2E tự động hóa toàn trình.

Tuy nhiên, để đồ án đạt mức **Xuất sắc / Điểm 10 tuyệt đối** và tiệm cận tiêu chuẩn vận hành của các trung tâm giám sát an ninh mạng (Next-Gen SOC) hiện đại, dưới đây là kế hoạch chi tiết cho **4 trụ cột cải tiến tiếp theo**.

---

## 🏛️ 4 Trụ Cột Nâng Cấp Trọng Yếu (Strategic Improvement Pillars)

### 1. 🤖 Trụ Cột 1: Tích hợp AI/LLM Triage vào SOAR (Bám sát xu hướng SOC 2025/2026)
* **Hiện trạng:** n8n đang làm giàu dữ liệu qua AbuseIPDB (trả về điểm số uy tín %) và sử dụng các mẫu văn bản tĩnh (Static Templates).
* **Mục tiêu nâng cấp:** Thêm một Node gọi **AI LLM (OpenAI / Claude / Google Gemini hoặc Ollama chạy Local)** vào Workflow 1 trong n8n:
  - **Tự động tóm tắt sự cố (Executive Summary):** Khi nhận Alert Sysmon thô (Event 10 LSASS Memory Access hoặc Event 1 Fodhelper UAC Bypass), AI sẽ phân tích cây tiến trình (Process Tree), dòng lệnh (CommandLine) và giải thích bằng ngôn ngữ tự nhiên:  
    > *"Cảnh báo mức độ nghiêm trọng: Tiến trình `powershell.exe` đang cố tình bypass cơ chế UAC thông qua việc can thiệp vào Registry `HKCU:\Software\Classes\ms-settings\...` nhằm chiếm quyền Local Administrator trái phép."*
  - **Sinh khuyến nghị hành động nhanh (Actionable Remediation):** Gợi ý cụ thể cho trực ca SOC L1 các bước xử lý (cần kill PID nào, thu hồi quyền user nào, hash file nào cần chặn trên EDR).
  - **Tự động điền báo cáo:** Nội dung tóm tắt và khuyến nghị của AI được đẩy trực tiếp vào thẻ tin nhắn Telegram và trường `description` của Ticket Jira Cloud.

---

### 2. 🛡️ Trụ Cột 2: Hoàn Thiện Quy Trình Phản Ứng Khép Kín (Closed-Loop Containment & Rollback) - [x] ĐÃ HOÀN THÀNH (100%)
* **Hiện trạng ban đầu:** Chỉ có nút `[🚫 Khóa IP 24h]` tạo rule DROP một chiều, chưa có cơ chế hoàn tác, chưa có phương án xử lý tấn công nội bộ (Host-internal).
* **Kết quả triển khai thành công:**
  - ✅ **Tính năng Mở khóa / Hoàn tác (Rollback Unblock):** Khi Analyst bấm `[🚫 Khóa IP 24h]`, thẻ xác nhận phản hồi ngay nút bấm `[🟢 Mở khóa IP (Rollback)]` (`action:unblock:${item.target}:${item.alert_id}`). Khi bấm nút, hệ thống thực thi xóa firewall rules tức thì (`Remove-NetFirewallRule`) qua WinRM và gửi tin nhắn xác nhận khôi phục dịch vụ.
  - ✅ **Tiêu diệt tiến trình độc hại (Kill Malicious Process):** Đối với các cảnh báo chuỗi Kill Chain (Rule 100004, 100005, 100007), ChatOps cung cấp nút `[🛑 Diệt Tiến Trình]` (`action:killproc:...`). SOAR thực thi `Stop-Process -Name <Target> -Force` qua WinRM để ngắt phiên điều khiển của tin tặc.
  - ✅ **Tự động dọn dẹp mã độc bám rễ (Persistence Cleanup):** Bổ sung nút `[🧹 Dọn Persistence]` (`action:cleanpersist:...`), SOAR tự động gỡ bỏ Registry Run Key (`WazuhLabPersistenceTest`) và xóa nhánh hijack UAC (`HKCU:\Software\Classes\ms-settings`).
  - ✅ **Tích hợp n8n & Telegram Bridge WinRM Engine:** Cập nhật đồng bộ `01_wazuh_soar_threat_enrichment.json` (bàn phím động phân luồng mạng vs nội bộ), `02_containment_action_executor.json` (6 nhánh routing hoàn chỉnh: block, unblock, killproc, cleanpersist, jira, ignore), và `telegram_bridge.py` hỗ trợ gọi WinRM trực tiếp sang Windows 10 Endpoint.
  - ✅ **Kiểm thử E2E khép kín:** Hoàn thiện bộ kiểm thử `tests/e2e/test_soar_closed_loop.py` đạt **15/15 PASS (100%)**.

---

### 3. 📊 Trụ Cột 3: Xây Dựng Dashboard Chuyên Biệt Trên Wazuh SIEM
* **Hiện trạng:** Kiểm tra cảnh báo chủ yếu qua file `alerts.json`, terminal console và Telegram.
* **Mục tiêu nâng cấp:**
  - Thiết kế và lưu trữ một **Custom Dashboard chuyên biệt** trên giao diện Web Wazuh Dashboard (Port 443) mang tên: `SOC Lab - Executive Incident Overview`:
    - **Pie Chart:** Tỷ lệ phân bố mức độ nghiêm trọng của Alert (Critical vs High vs Medium).
    - **MITRE ATT&CK Matrix Heatmap:** Trực quan hóa các kỹ thuật đã phát hiện và xác thực thành công (`T1110.001`, `T1190`, `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001`).
    - **Bar Chart:** Thống kê Top IP nguồn phát động tấn công nhiều nhất (Kali `192.168.71.130`).
    - **Metric Widgets:** Thời gian trung bình tiếp nhận cảnh báo (MTTA < 3s) và phản ứng ngăn chặn (MTTR < 20s).
  - Xuất file cấu hình Dashboard này thành tệp `.ndjson` lưu trữ tại thư mục `deployment/dashboards/` để cho phép người dùng Import 1-click lên bất kỳ cụm Wazuh nào.

---

### 4. 🔄 Trụ Cột 4: Tích Hợp CI/CD Pipeline Cho Detection Engineering (GitHub Actions) - [x] ĐÃ HOÀN THÀNH (100%)
* **Hiện trạng ban đầu:** Kỹ sư chạy bộ kiểm thử đơn vị (`pytest tests/unit/`) thủ công trên máy cục bộ trước khi commit, tiềm ẩn nguy cơ đẩy nhầm cú pháp XML lỗi làm sập engine phân tích `wazuh-analysisd`.
* **Kết quả triển khai thành công:**
  - ✅ **Pipeline Tự Động Hóa CI/CD:** Thiết lập workflow chuẩn doanh nghiệp [`.github/workflows/test.yml`](.github/workflows/test.yml) tự động kích hoạt khi có Push hoặc Pull Request tác động vào các file rules, decoders, configs và tests.
  - ✅ **Hỗ Trợ Ma Trận Đa Môi Trường:** Kiểm thử song song trên môi trường Ubuntu đám mây với Python `3.10` và `3.11`.
  - ✅ **Mở Rộng 12 Tiêu Chí Kiểm Thử Đơn Vị (12 Checks):** Nâng cấp [tests/unit/test_detection_config.py](tests/unit/test_detection_config.py) đạt **12/12 PASS (100%)**:
    1. Cú pháp XML Well-formedness cho toàn bộ Rules, Decoders, `ossec.conf` và `sysmon-config.xml`.
    2. Định danh Rule ID duy nhất và tuân thủ namespace tùy biến `>= 100000`.
    3. Giới hạn cấp độ cảnh báo Wazuh hợp lệ (Severity Level 0–16).
    4. Cú pháp mã kỹ thuật MITRE ATT&CK chuẩn (`Txxxx` / `Txxxx.xxx`).
    5. Phát hiện RDP Brute Force (Rule 100001, T1110).
    6. Phát hiện Web LFI / Path Traversal (Rule 100002, T1190).
    7. Bộ giải mã Apache Web Access log (`web-access-lfi`).
    8. Bộ 4 quy tắc MITRE Windows Kill Chain (T1059.001, T1548.002, T1547.001, T1003.001).
    9. Luật ức chế phân cấp (Hierarchical Suppression Rules 100008, 100009, 100010) cho SOAR WinRM `socrunner` (Level 0, AND logic).
    10. Biên dịch an toàn biểu thức chính quy Regex & PCRE2.
    11. Kiến trúc tích hợp duy nhất: 1 khối `<integration>` cho `custom-n8n` webhook.
    12. Tuân thủ chính sách Zero Secret Leakage: Không rò rỉ token/mật khẩu trong file mẫu template.
  - ✅ **Tích Hợp Báo Cáo CI Trực Quan ($GITHUB_STEP_SUMMARY):** Tự động xuất bảng tổng kết trạng thái chi tiết ngay trong giao diện GitHub Actions Summary của mỗi lần chạy.
  - ✅ **Gắn Huy Hiệu Trạng Thái:** Nhúng trực tiếp huy hiệu build xanh `Detection Engineering CI` ngay trên đầu trang [README.md](README.md).
  - ✅ **Tài Liệu Hướng Dẫn Kỹ Thuật:** Biên soạn đầy đủ [tests/unit/README.md](tests/unit/README.md) cẩm nang vận hành bộ test.

---

## 🎯 Bảng Lộ Trình Ưu Tiên & Phân Kỳ Thực Hiện (Phasing Matrix)

| Giai Đoạn | Hạng Mục Công Việc | Mức Độ Ưu Tiên | Độ Khó | Giá Trị Mang Lại Cho Đồ Án / Đánh Giá |
| :---: | :--- | :---: | :---: | :--- |
| **P1** | **Nhúng sơ đồ Architecture Diagram (Eraser.io) & Hoàn thiện Visual Showcase trong `README.md`** | **Ưu tiên 1 (Làm ngay)** | Rất Dễ | Tạo ấn tượng thị giác chuyên nghiệp ngay từ cái nhìn đầu tiên cho hội đồng chấm. |
| **P2** | **Tích hợp Node AI LLM (Gemini / OpenAI API) vào n8n để phân tích & tóm tắt sự cố tự động** | **Ưu tiên 2 (Trọng tâm)** | Vừa phải | Bắt kịp xu hướng AI trong An ninh mạng (AI-driven SOC), ghi điểm tuyệt đối về tính sáng tạo. |
| **P3** | **Tạo pipeline GitHub Actions CI tự động chạy Unit Test khi đẩy code (Detection-as-Code)** | **Ưu tiên 3 (Kỹ thuật)** | Dễ | Thể hiện tư duy chuẩn DevSecOps của các doanh nghiệp và tập đoàn công nghệ lớn. |
| **P4** | **Bổ sung tính năng Rollback `[🟢 Mở khóa IP]` và diệt tiến trình độc hại qua WinRM** | **Ưu tiên 4 (Vận hành)** | Vừa phải | Hoàn thiện quy trình ứng phó sự cố khép kín (Closed-Loop Incident Response) theo chuẩn NIST. |

---

## 🛠️ Danh Mục Tài Nguyên Kỹ Thuật Cần Chuẩn Bị

1. **Cho Trụ Cột 1 (AI LLM):**
   - API Key Google Gemini (miễn phí) hoặc OpenAI API Key.
   - Bổ sung biến môi trường `GEMINI_API_KEY` vào `.env.example` và script `sync_env.py`.
2. **Cho Trụ Cột 2 (Rollback):**
   - Cập nhật inline keyboard Telegram trong Workflow 1 & 2 để bổ sung callback `action:unblock`.
   - Bổ sung khối lệnh WinRM xóa rule: `Remove-NetFirewallRule -DisplayName "SOAR-BLOCK-..."`.
3. **Cho Trụ Cột 3 (Wazuh Dashboard):**
   - Truy cập giao diện OpenSearch Dashboards (Port 443) -> *Saved Objects* -> *Export*.
4. **Cho Trụ Cột 4 (CI/CD):**
   - Khởi tạo thư mục `.github/workflows/` và file `test.yml` chạy môi trường `python:3.11-slim`.

---

## 🌐 5 Hướng Mở Rộng Tiềm Năng Cho Hệ Thống SOC Doanh Nghiệp (Next-Gen SOC Expansion)

Ngoài 4 trụ cột trọng tâm về AI, Rollback, Dashboard và CI/CD, để tiệm cận toàn diện tiêu chuẩn của một **Trung tâm Điều hành An ninh mạng Doanh nghiệp (Enterprise Cyber Defense Center / Next-Gen SOC)**, dưới đây là 5 hướng nâng cấp mở rộng cực kỳ đắt giá:

### 1. 🍯 Công Nghệ Bẫy Mồi & Đánh Lừa Kẻ Tấn Công (Deception Technology / Honeypots)
* **Ý tưởng:** Đây là một trong những công nghệ phòng thủ chủ động hiện đại nhất. Thay vì chỉ chờ tin tặc tấn công vào máy thật, hệ thống chủ động rải các "mồi nhử" (Decoys) trong mạng nội bộ.
* **Phương án triển khai:**
  - **Canary Tokens / Honey-tokens:** Tạo một file giả mang tên `passwords_production.xlsx` trên máy Windows 10, hoặc một tài khoản giả `admin_backup` không bao giờ sử dụng trong vận hành thông thường.
  - Khi tin tặc xâm nhập máy và tò mò mở file này hoặc cố đăng nhập tài khoản đó $\rightarrow$ Wazuh lập tức phát hiện với **tỷ lệ báo động giả bằng 0% (Zero False Positive)**.
  - Hoặc triển khai một **Honeypot SSH/RDP siêu nhẹ (như OpenCanary hoặc Cowrie)** để dụ tin tặc tấn công vào máy giả.
* **Giá trị thực tiễn:** Thể hiện tư duy **Phòng thủ chủ động (Active Cyber Defense)**, tạo điểm nhấn độc đáo hiếm có trong các đồ án an ninh mạng.

---

### 2. 🌐 Giám Sát Tầng Mạng Sâu Bằng NIDS (Tích hợp Suricata / Zeek)
* **Ý tưởng:** Hiện tại hệ thống chủ yếu giám sát ở tầng Endpoint (máy trạm qua Sysmon và Log hệ điều hành). Bổ sung thêm tầng **Network Traffic Analysis (Phân tích gói tin mạng chuyên sâu)** sẽ tạo nên bộ đôi hoàn chỉnh: **EDR + NIDS = XDR**.
* **Phương án triển khai:**
  - Cài đặt **Suricata** trên máy Ubuntu (Wazuh Manager) hoặc cấu hình một sensor lắng nghe card mạng ảo.
  - Suricata phân tích lưu lượng mạng và xuất log chuẩn `eve.json` $\rightarrow$ Wazuh đọc file này để tương quan phát hiện:
    - Kỹ thuật quét cổng lén lút (Stealth SYN scan) của Nmap.
    - Hành vi gián điệp mạng và lưu lượng bất thường (C2 Beaconing của Cobalt Strike/Sliver, DNS Tunneling).
* **Giá trị thực tiễn:** Nâng tầm phòng Lab từ SIEM đơn thuần thành hệ thống **XDR (Extended Detection and Response)** toàn diện cả máy trạm lẫn lưu lượng mạng.

---

### 3. 📜 Chuẩn Hóa Luật Phát Hiện Bằng Ngôn Ngữ Sigma (Sigma Rules Integration)
* **Ý tưởng:** Thay vì chỉ viết rule bằng cú pháp đặc thù của Wazuh XML, áp dụng chuẩn **Sigma** — ngôn ngữ mở tiêu chuẩn quốc tế được các kỹ sư Detection Engineering toàn cầu sử dụng để mô tả chữ ký phát hiện độc lập với nền tảng SIEM.
* **Phương án triển khai:**
  - Viết các file luật theo định dạng YAML chuẩn Sigma (ví dụ: `uac_bypass_fodhelper.yml`).
  - Sử dụng công cụ `pySigma` hoặc `sigmac` để tự động chuyển đổi file YAML thành định dạng XML của Wazuh.
* **Giá trị thực tiễn:** Chứng minh năng lực làm việc theo tiêu chuẩn công nghiệp quốc tế, mã nguồn phát hiện có thể tái sử dụng trên Splunk, Elastic, Sentinel hay Wazuh mà không phải viết lại từ đầu.
* Có thể là sẽ tạo thêm 1 UI trên wazuh dashboard lưu trữ các rule đã tạo và 1 hộp 'Box' để điền luật mới và save nó.
---

### 4. 🗃️ Tích Hợp Nền Tảng Threat Intelligence Tập Trung (MISP / OpenCTI)
* **Ý tưởng:** Thay vì tra cứu AbuseIPDB và VirusTotal theo kiểu "hỏi từng IP đơn lẻ" khi sự cố đã xảy ra, hệ thống tự động đồng bộ hàng nghìn IoC độc hại từ các nguồn tình báo quốc tế.
* **Phương án triển khai:**
  - Tích hợp nguồn cấp dữ liệu tình báo mối đe dọa (Threat Intel Feeds) từ **AlienVault OTX** hoặc nền tảng **MISP**.
  - Tự động nạp danh sách đen IP/Domain độc hại vào cơ sở dữ liệu **CDB List** của Wazuh (`/var/ossec/etc/lists`).
  - Bất cứ khi nào máy trạm kết nối tới một IP trong danh sách đen $\rightarrow$ Wazuh báo động ngay lập tức ở cấp độ mạng nội bộ mà không tốn quota API ra ngoài.
* **Giá trị thực tiễn:** Tối ưu hóa hiệu năng, giảm phụ thuộc vào API bên thứ ba và tăng tốc độ phát hiện xuống mức mili-giây.

---

### 5. 🔍 Quản Lý Lỗ Hổng & Đánh Giá Tuân Thủ (Vulnerability Detection & SCA)
* **Ý tưởng:** Bên cạnh việc ứng phó khi bị tấn công (Reactive), SOC hiện đại cần đảm bảo khả năng **phòng ngừa và quản trị rủi ro sớm (Proactive Vulnerability Management)**.
* **Phương án triển khai:**
  - Kích hoạt module **Vulnerability Detector** có sẵn trong Wazuh Manager: Wazuh Agent tự động quét danh mục phần mềm trên Windows 10 (Apache, XAMPP, WinRAR, Chrome...) và đối soát với cơ sở dữ liệu quốc gia NVD (National Vulnerability Database) để báo cáo các mã CVE nguy hiểm chưa được vá.
  - Kích hoạt module **SCA (Security Configuration Assessment)** để chấm điểm tuân thủ an toàn máy trạm theo chuẩn **CIS Benchmark** (phát hiện mật khẩu yếu, chưa bật BitLocker, cổng RDP mở mặc định...).
* **Giá trị thực tiễn:** Mở rộng phạm vi đồ án từ "Giám sát & Ứng phó sự cố" sang toàn diện cả "Đánh giá & Quản trị rủi ro an ninh mạng".

---

### 📊 Bảng Đánh Giá Mức Độ Ấn Tượng Của Các Hướng Mở Rộng

| Hướng Mở Rộng | Độ Khó | Mức Độ Ấn Tượng & Giá Trị Đồ Án | Phù Hợp Cho Định Hướng Nghề Nghiệp |
| :--- | :---: | :---: | :--- |
| **1. Deception / Canary Tokens** | **Dễ - Vừa** | ⭐⭐⭐⭐⭐ (Rất cao) | SOC Analyst, Threat Hunter, Blue Team |
| **2. NIDS Suricata (Thành XDR)** | **Vừa phải** | ⭐⭐⭐⭐⭐ (Rất cao) | Security Engineer, Network Security |
| **3. Chuẩn hóa Sigma Rules** | **Dễ** | ⭐⭐⭐⭐ (Cao) | Detection Engineer, DevSecOps |
| **4. Threat Intel Feeds / MISP** | **Vừa - Khó** | ⭐⭐⭐⭐ (Cao) | CTI Analyst (Cyber Threat Intelligence) |
| **5. Vulnerability & CIS Benchmark** | **Rất Dễ** (Có sẵn trong Wazuh) | ⭐⭐⭐⭐ (Cao) | Security Compliance, Vulnerability Management |

> 💡 **Lời khuyên thực tế:** Nếu muốn bổ sung thêm 1 hạng mục thực nghiệm nhanh nhất nhưng mang lại hiệu quả thị giác và tính thuyết phục cao nhất cho đồ án, hãy ưu tiên chọn **Hướng 1 (Tạo Canary Token / Bẫy mồi)** hoặc **Hướng 5 (Bật Vulnerability Detector của Wazuh)** vì cả hai đều cấu hình rất nhanh và đưa vào slide thuyết trình cực kỳ nổi bật!
