# 🔄 Phase 6: DevSecOps CI/CD Pipeline (GitHub Actions)

Thư mục lưu trữ báo cáo kỹ thuật và minh chứng của **Phase 6**, triển khai quy trình CI/CD tự động kiểm định chất lượng luật phát hiện (Detection Engineering) theo chuẩn doanh nghiệp.

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-6_Detection-Engineering-CICD-Pipeline.md`](Phase-6_Detection-Engineering-CICD-Pipeline.md)
* **Nội dung:**
  - Thiết kế GitHub Actions workflow chạy trên môi trường đa phiên bản Python (`3.10`, `3.11`).
  - Bộ 22 bài kiểm thử tự động (Pytest Unit Checks): kiểm tra cú pháp XML, tính duy nhất của Rule ID, dải mức độ nghiêm trọng (0–16), format kỹ thuật MITRE ATT&CK, an toàn biên dịch Regex/PCRE2, và quy chuẩn Zero Secret Leakage.
  - Tự động chặn các commit hoặc Pull Request vi phạm trước khi đưa vào môi trường sản xuất.
