# 🧪 Test Automation Framework (Detection-as-Code)

Thư mục lưu trữ toàn bộ khung kiểm thử tự động hóa của đồ án, bao gồm **Kiểm thử đơn vị (Unit Tests)** trong CI/CD Pipeline và **Kiểm thử đầu-cuối (End-to-End Tests)** trên môi trường thực tế.

---

## 🗂️ Cấu Trúc Khung Kiểm Thử

| Phân Hệ | Đường Dẫn | Mục Đích Kiểm Thử |
| :--- | :--- | :--- |
| **Unit Testing (CI/CD)** | [`unit/`](unit/) | Chạy 22 bài kiểm thử tự động xác thực cú pháp XML Rules, Decoders, Regex PCRE2, định dạng MITRE ATT&CK, và chuẩn bảo mật Zero Secret Leakage. Được kích hoạt bởi GitHub Actions. |
| **End-to-End Testing (E2E)** | [`e2e/`](e2e/) | Kịch bản tự động hóa tấn công giả lập từ Kali Linux $\rightarrow$ Windows Endpoint $\rightarrow$ Wazuh SIEM $\rightarrow$ SOAR Telegram/Jira. Kiểm toán luồng sự kiện thực tế. |

---

## ⚡ Lệnh Thực Thi Kiểm Thử
* **Chạy kiểm thử đơn vị cục bộ:**
  ```powershell
  pytest tests/unit/ -v
  ```
* **Chạy kiểm tra sức khỏe 3 máy ảo:**
  ```powershell
  python tests/e2e/lab_health.py
  ```
* **Chạy kịch bản tấn công Full Kill Chain:**
  ```powershell
  python tests/e2e/scenario_full_killchain.py --execute
  ```
