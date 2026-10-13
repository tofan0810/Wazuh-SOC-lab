# 📘 BỘ QUY TRÌNH ỨNG PHÓ SỰ CỐ AN NINH MẠNG (SOC INCIDENT RESPONSE PLAYBOOKS)

Tài liệu này chuẩn hóa quy trình tiếp nhận, điều tra, cô lập, khôi phục và bảo tồn chứng cứ số (Standard Operating Procedures - SOP) dành cho đội ngũ vận hành **SOC Analyst (L1/L2)**, **Incident Responder** và **DFIR Specialist**, tuân thủ theo tiêu chuẩn quốc tế **NIST SP 800-61 Rev. 2** và chu trình **SANS PICERL**.

---

## 🧭 Khung Quy Trình Ứng Phó Sự Cố (NIST / SANS Framework)

```
       ┌────────────────────────┐
       │   1. PREPARATION       │ (Chuẩn bị: Cấu hình Sysmon, Rules, Suricata, Deception Grid)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   2. IDENTIFICATION    │ (Phát hiện & Phân loại: Triage, Severity, Zero False Positive)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   3. CONTAINMENT       │ (Cô lập: 1-Click Safe Host Isolation, Active Response, WinRM Drop)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   4. ERADICATION       │ (Diệt trừ: Diệt tiến trình, Dọn Registry Run, Khóa tài khoản)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   5. RECOVERY          │ (Khôi phục: 1-Click Rollback 5s, Đổi mật khẩu, Giám sát tăng cường)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   6. LESSONS LEARNED   │ (Hậu sự cố: Họp rút kinh nghiệm, Tối ưu Sigma Rules, Jira RCA)
       └────────────────────────┘
```

---

## 📊 Ma Trận Phân Loại Mức Độ Nghiêm Trọng (Severity Matrix)

| Cấp độ | Định nghĩa | Tiêu chí kích hoạt | SLA Phản hồi |
| :--- | :--- | :--- | :---: |
| **P1 - Critical** | Sự cố nghiêm trọng đe dọa toàn bộ hệ thống; lộ thông tin xác thực quản trị hoặc chạm vào bẫy mồi Deception. | • Tương tác bẫy mồi Deception Honey-File / Honey-Account (0% FP).<br/>• Dump bộ nhớ `lsass.exe` thành công.<br/>• Đăng nhập thành công sau chuỗi Brute Force (Event 4624 Type 10). | **< 15 phút**<br/>*(Tự động tức thì)* |
| **P2 - High** | Tấn công có chủ đích đang diễn ra; thực thi mã độc hoặc leo quyền UAC trên máy trạm. | • Kích hoạt PowerShell mã hóa Base64 (`T1059.001`).<br/>• Hijack registry UAC Bypass `ms-settings` (`T1548.002`).<br/>• Web LFI đọc thành công file cấu hình hệ thống trên dây mạng. | **< 30 phút** |
| **P3 - Medium** | Hoạt động do thám mạng hoặc tấn công tự động số lượng lớn đã bị Active Response chặn. | • Quét cổng Nmap Stealth SYN bắt bởi Suricata NIDS (`T1046`).<br/>• Máy quét lỗ hổng tự động (Nikto, Gobuster) thăm dò cổng Web.<br/>• RDP Brute Force bị chặn thành công bởi Firewall. | **< 2 giờ** |
| **P4 - Low** | Hoạt động bất thường đơn lẻ, khả năng cao là người dùng nhập nhầm mật khẩu. | • 1–3 lần đăng nhập thất bại từ máy người dùng nội bộ.<br/>• Request HTTP lỗi cú pháp 404 thông thường. | **< 8 giờ** |

---

## 🗂️ Danh Mục Toàn Diện 6 Playbook Vận Hành (SOP-01 Đến SOP-06)

| Mã SOP | Tên Quy Trình Chuẩn (Standard Operating Procedure) | Kỹ Thuật MITRE | Phân Hệ Áp Dụng |
| :---: | :--- | :---: | :--- |
| [**SOP-01**](SOP-01_RDP_Brute_Force_Response.md) | **Ứng phó Tấn công Dò quét Mật khẩu RDP** | **T1110.001** | Windows Security Event ID 4625 & Netsh Firewall Drop |
| [**SOP-02**](SOP-02_Web_LFI_Mitigation.md) | **Ứng phó Khai thác Lỗ hổng Ứng dụng Web LFI & Path Traversal** | **T1190** | Apache Access Logs, Sysmon Event ID 1 & 11 |
| [**SOP-03**](SOP-03_SOAR_Automated_Containment.md) | **Ứng phó Tự động hóa qua SOAR & Phản ứng Khép kín (Rollback 5s)** | **T1110, T1190, T1059** | n8n SOAR, Telegram ChatOps 2-Way, Jira Cloud REST v3 |
| [**SOP-04**](SOP-04_Endpoint_Kill_Chain_Response.md) | **Ứng phó Chuỗi Tấn công Malware & Chiếm đoạt LSASS Credentials** | **T1059, T1548, T1547, T1003** | Sysmon Event ID 1, 10, 12, 13 & Active Response `kill-process` |
| [**SOP-05**](SOP-05_Network_NIDS_Suricata_Response.md) | **Ứng phó Xâm nhập Tầng mạng Suricata NIDS & Tương quan XDR** | **T1046, T1595, T1190** | Suricata 8.0.7 EVE JSON Stream (`ens33`) & Packet Analysis |
| [**SOP-06**](SOP-06_Deception_Honeypot_and_Forensics.md) | **Ứng phó Bẫy mồi Deception (0% FP) & Thu thập Pháp y số DFIR** | **T1083, T1078, T1046** | Windows SACL 4663, Honey-Account, FTP Decoy & RAM MiniDump |
