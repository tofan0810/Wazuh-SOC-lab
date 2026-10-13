# 📜 Phase 8: Detection-as-Code Với Ngôn Ngữ Sigma (SSOT)

Thư mục lưu trữ báo cáo kỹ thuật của **Phase 8**, chuẩn hóa toàn bộ tập luật phát hiện sang ngôn ngữ **Sigma Rules** chuẩn mở quốc tế theo mô hình Single Source of Truth (SSOT).

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-8_Sigma-Rules-Integration.md`](Phase-8_Sigma-Rules-Integration.md)
* **Nội dung:**
  - Chuyển đổi toàn bộ quy tắc phát hiện sang Sigma YAML tại [`custom-rules/sigma/`](../../custom-rules/sigma/).
  - Phát triển bộ biên dịch độc quyền **SigWaz Core Engine** ([`scripts/sigma_compiler.py`](../../scripts/sigma_compiler.py)) tự động chuyển đổi Sigma sang XML chuẩn của Wazuh.
  - Tự động sinh luật ức chế phân cấp (`level="0"`) cho tài khoản SOAR `socrunner`.
  - Cơ chế **Zero-Drift Enforcement** tích hợp vào CI/CD Pipeline đảm bảo không có sự lệch pha giữa mã nguồn luật Sigma và XML đang chạy.
