# ⚡ Phase 5: Điều Phối SOAR & Phản Ứng Khép Kín (Closed-Loop)

Thư mục lưu trữ các tài liệu báo cáo kỹ thuật và minh chứng của **Phase 5**, triển khai hệ thống điều phối phản ứng tự động hóa SOAR với n8n, Telegram ChatOps và Atlassian Jira Cloud.

---

## 📌 Danh Mục Báo Cáo Kỹ Thuật

| Báo Cáo | Nội Dung Trọng Tâm |
| :--- | :--- |
| [`Phase-5_SOAR-Workflow-Automation.md`](Phase-5_SOAR-Workflow-Automation.md) | **Phần 1: Thiết kế SOAR & Tích hợp:** Triển khai n8n trên Docker, kết nối webhook Wazuh, làm giàu IoC qua AbuseIPDB/VirusTotal, gửi card HTML cảnh báo Telegram kèm nút tương tác, và tích hợp Jira Cloud REST API v3. |
| [`Phase-5_Closed-Loop-Containment-and-Rollback.md`](Phase-5_Closed-Loop-Containment-and-Rollback.md) | **Phần 2: Phản ứng khép kín & Hoàn tác:** Cơ chế **1-Click Safe Host Isolation** (giữ port 5985 & 1514/1515), diệt tiến trình độc hại, dọn dẹp Registry persistence và tính năng **1-Click Rollback giải phóng mạng trong 5 giây**. |
