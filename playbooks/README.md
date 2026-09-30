# 📘 BỘ QUY TRÌNH ỨNG PHÓ SỰ CỐ AN NINH MẠNG (SOC INCIDENT RESPONSE PLAYBOOKS)

Tài liệu này chuẩn hóa quy trình tiếp nhận, điều tra, cô lập và khắc phục sự cố (Standard Operating Procedures - SOP) dành cho đội ngũ vận hành **SOC Analyst (L1/L2)** và **Incident Responder**, tuân thủ theo tiêu chuẩn quốc tế **NIST SP 800-61 Rev. 2** và chu trình **SANS PICERL**.

---

## 🧭 Khung Quy Trình Ứng Phó Sự Cố (NIST / SANS Framework)

```
       ┌────────────────────────┐
       │   1. PREPARATION       │ (Chuẩn bị: Cấu hình Sysmon, Rules, Baseline)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   2. IDENTIFICATION    │ (Phát hiện & Phân loại: Triage, Severity, False Positive)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   3. CONTAINMENT       │ (Cô lập: Active Response, Chặn IP, Tách ly máy nạn nhân)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   4. ERADICATION       │ (Diệt trừ: Khóa tài khoản, Xóa mã độc, Diệt Web Shell)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   5. RECOVERY          │ (Khôi phục: Đổi mật khẩu, Mở dịch vụ, Giám sát tăng cường)
       └───────────┬────────────┘
                   ▼
       ┌────────────────────────┐
       │   6. LESSONS LEARNED   │ (Hậu sự cố: Họp rút kinh nghiệm, Hardening, Tuning Rules)
       └────────────────────────┘
```

---

## 📊 Ma Trận Phân Loại Mức Độ Nghiêm Trọng (Severity Matrix)

| Cấp độ | Định nghĩa | Tiêu chí kích hoạt | Thời gian phản hồi tối đa (SLA) |
| :--- | :--- | :--- | :--- |
| **P1 - Critical** | Sự cố thảm họa, kẻ tấn công đã chiếm quyền điều khiển hệ thống, lộ dữ liệu nhạy cảm. | Kẻ tấn công đăng nhập thành công sau chuỗi Brute Force (Event 4624 Type 10); Hoặc LFI dẫn tới thực thi mã từ xa (RCE / Web Shell). | **< 15 phút** |
| **P2 - High** | Tấn công có chủ đích đang diễn ra dồn dập, Active Response thất bại hoặc bị vượt qua. | Brute Force > 50 attempts/phút nhưng chưa bị Firewall chặn; LFI đọc thành công file cấu hình `win.ini` / `web.config`. | **< 30 phút** |
| **P3 - Medium** | Tấn công tự động số lượng lớn nhưng đã bị ngăn chặn thành công bởi Active Response. | Rule 100001 kích hoạt và IP tấn công đã bị khóa bởi Windows Firewall trong 600s; Quét dò LFI thất bại (404/403). | **< 2 giờ** |
| **P4 - Low** | Hoạt động bất thường đơn lẻ, khả năng cao là người dùng quên mật khẩu hoặc máy quét mạng nội bộ. | 1-3 lần đăng nhập thất bại từ máy người dùng nội bộ; Request lỗi cú pháp thông thường. | **< 8 giờ** |

---

## 🗂️ Danh Mục Các Playbook Trong Thư Mục

1. [**SOP-01: Ứng phó Tấn công Dò quét Mật khẩu RDP (T1110 - Brute Force)**](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/playbooks/SOP-01_RDP_Brute_Force_Response.md)
   * Phân biệt giữa người dùng quên mật khẩu và tấn công tự động.
   * Xử lý tình huống Active Response tự động bị lỗi.
   * Kiểm tra dấu hiệu xâm nhập thành công (Event ID 4624 Logon Type 10).
   * Biện pháp phòng vệ và Hardening: NLA, Account Lockout Policy.

2. [**SOP-02: Ứng phó Khai thác Lỗ hổng Ứng dụng Web (T1190 - Local File Inclusion & Web Shell)**](file:///D:/Downloads/ATTT/Wazuh-SOC-lab/playbooks/SOP-02_Web_LFI_Mitigation.md)
   * Phân tích Apache Access Log và bóc tách chuỗi URL (Single & Double Encoding).
   * Rà soát Web Shell và hành vi leo thang bằng Sysmon Event ID 1 và 11.
   * Vá lỗ hổng mã nguồn PHP và cô lập ứng dụng Web.
   * Biện pháp phòng vệ: `open_basedir`, Whitelisting, WAF rule.
