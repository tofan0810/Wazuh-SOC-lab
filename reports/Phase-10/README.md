# 🍯 Phase 10: Bẫy Mồi Deception & Tự Động Thu Thập DFIR

Thư mục lưu trữ báo cáo kỹ thuật và minh chứng của **Phase 10**, nâng cấp hệ thống phòng thủ từ bị động sang chủ động (**Active Defense**) bằng công nghệ bẫy mồi và bảo toàn chứng cứ số tự động.

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-10_Deception-Technology-Honeypots.md`](Phase-10_Deception-Technology-Honeypots.md)
* **Nội dung:**
  - Thiết lập mạng lưới bẫy mồi 3 tầng: Canary Honey-File (Windows SACL Event ID 4663), Honey-Account `backup_admin` (Event ID 4625), và Network Service Decoy (TCP Port 21 FTP Listener).
  - Đạt tiêu chuẩn **Zero False Positive (0% cảnh báo giả)**, tự động khóa IP kẻ tấn công tức thì.
  - Module **Bảo tồn chứng cứ số tự động (Automated Live DFIR Preservation)**: tự động gom RAM mini-dump của tiến trình vi phạm, kết nối mạng `netstat`, active sessions và file `.evtx`, nén file `.zip` và tự động đính kèm lên **Jira Cloud Incident Ticket**.
