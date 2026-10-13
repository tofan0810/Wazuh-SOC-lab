# 🔄 Phase 4: Tự Động Hóa Kiểm Thử Hồi Quy (Regression Testing)

Thư mục lưu trữ tài liệu và ảnh minh chứng thực nghiệm của **Phase 4**, tập trung vào việc tự động hóa quá trình kiểm thử hồi quy kịch bản tấn công và xác thực độ chính xác của tập luật SIEM.

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-4_Regression-Test-Automation.md`](Phase-4_Regression-Test-Automation.md)
* **Nội dung:**
  - Thiết kế bộ script kiểm thử E2E tự động hóa bằng Python (`tests/e2e/`).
  - Kiểm tra kết nối và tính sẵn sàng của 3 máy ảo (`lab_health.py`).
  - Tự động phát động tấn công từ xa qua SSH/WinRM, theo dõi luồng log `alerts.json` và xác nhận kết quả kiểm thử đạt 100%.
  - Cơ chế tự động dọn dẹp hiện trường (Eradication & Cleanup) sau mỗi đợt kiểm thử.
