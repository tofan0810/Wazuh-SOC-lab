# BẢN CẬP NHẬT PHASE 5: CLOSED-LOOP CONTAINMENT & INSTANT ROLLBACK
> **Tài liệu bổ sung (Addendum)** cho báo cáo chính [`Phase-5_SOAR-Workflow-Automation.md`](Phase-5_SOAR-Workflow-Automation.md)  
> **Thời gian cập nhật:** Tháng 10/2026

---

## 🚀 TỔNG HỢP CÁC ĐIỂM NÂNG CẤP MỚI (WHAT WAS UPDATED)

So với phiên bản SOAR ban đầu (chỉ hỗ trợ chặn IP một chiều), bản cập nhật này bổ sung 4 tính năng chiến lược:

1. **Khép kín quy trình & Tự phục hồi (1-Click Rollback):**
   - Khi bấm cô lập hoặc chặn IP, Telegram tự động sinh nút **`[🟢 Unblock IP (Rollback)]`**.
   - Khôi phục dịch vụ tức thì dưới 5 giây nếu chặn nhầm, không cần truy cập máy trạm gõ lệnh thủ công.

2. **Mở rộng năng lực can thiệp tầng Host (Endpoint Eradication):**
   - **`[🛑 Kill Process]`**: Tiêu diệt tức thời tiến trình mã độc (`Stop-Process -Force`) cắt đứt phiên tương tác của hacker.
   - **`[🧹 Clean Persistence]`**: Tự động dọn sạch Registry Run Key (`HKCU:...\CurrentVersion\Run`) và cấu hình UAC Hijacking (`HKCU:...\Classes\ms-settings`).
   - **`[🔒 Isolate Host]`**: Cách ly máy khỏi Kali và mạng ngoài nhưng **bảo lưu thông suốt WinRM (5985) và Wazuh Agent (1514)** để không bị mất kết nối quản trị.

3. **Triệt tiêu hoàn toàn bão cảnh báo (Feedback Storm Elimination):**
   - Dọn sạch các block `<integration>` trùng lặp trong `ossec.conf`, loại bỏ integration cũ `custom-telegram`.
   - Áp dụng **Mô hình Luật phân cấp (Rule con 100008 Level 0)** để tự động bỏ qua các lệnh can thiệp của tài khoản `socrunner` chạy qua CMD/WinRM.

---

## 📊 BẢNG SO SÁNH NHANH (DIFF MATRIX)

| Tiêu Chí | Bản Cũ (Phase 5 v1) | Bản Cập Nhật Mới (Trụ Cột 2) |
| :--- | :--- | :--- |
| **Quy trình phản ứng** | Một chiều (Chặn xong là hết) | **Khép kín (Chặn $\rightarrow$ Sinh nút Hoàn tác)** |
| **Nút bấm Telegram** | Tĩnh, cố định cho mọi alert | **Động, thích ứng theo hành vi (Mạng vs Nội bộ)** |
| **Can thiệp Host** | ❌ Không hỗ trợ | **✅ Diệt Process, Dọn Registry, Cô lập an toàn** |
| **Nguy cơ gián đoạn** | Cao (Khóa nhầm làm ngắt hệ thống) | **Gần như bằng 0 (Có thể Rollback 1-click ngay)** |
| **Bão cảnh báo (Loop)** | ❌ Bị lặp 3-4 tin nhắn khi bấm nút | **✅ Triệt tiêu 100% bằng Luật phân cấp Level 0** |
| **Ngôn ngữ ChatOps** | Tiếng Việt chưa đồng bộ | **100% Tiếng Anh chuẩn Enterprise SOC** |
| **Kiểm thử tự động** | Kiểm thử thủ công từng bước | **Suite tự động 15/15 test cases (PASS 100%)** |
