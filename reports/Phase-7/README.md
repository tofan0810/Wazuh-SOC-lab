# 📊 Phase 7: Executive Incident Dashboard

Thư mục lưu trữ báo cáo kỹ thuật và minh chứng của **Phase 7**, thiết kế và triển khai giao diện trực quan hóa sự cố chuyên nghiệp trên nền tảng **OpenSearch Dashboards** (Wazuh Dashboard Port 443).

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-7_Executive-Incident-Dashboard.md`](Phase-7_Executive-Incident-Dashboard.md)
* **Nội dung:**
  - Thiết kế Dashboard **`SOC Lab - Executive Incident Overview`** gồm 7 Visualizations chuyên biệt (KPI MTTA/MTTR, Donut chart phân bổ mức độ, Heatmap MITRE ATT&CK, Leaderboard IP kẻ tấn công, Bảng Endpoint & User, Malicious Processes, và Real-time Incident Stream).
  - Tự động hóa xuất bản và nạp nhanh (1-Click Import) toàn bộ 9 Saved Objects qua REST API chỉ trong 1.5 giây bằng script [`scripts/import_dashboard.py`](../../scripts/import_dashboard.py).
