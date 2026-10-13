# ⚙️ Operations & Automation Scripts

Thư mục lưu trữ các kịch bản Python tự động hóa vận hành, quản trị cấu hình và biên dịch quy tắc phát hiện của hệ sinh thái **Wazuh SOC Lab**.

---

## 📌 Danh Mục Scripts

| Script | Mục Đích & Chức Năng | Cách Sử Dụng |
| :--- | :--- | :--- |
| `sync_env.py` | **Đồng bộ hóa môi trường:** Đọc biến từ `.env`, kiểm tra tính sống còn của các API (Telegram, Jira, AbuseIPDB, VirusTotal), và đồng bộ cấu hình sang Wazuh Manager & n8n. | `python scripts/sync_env.py`<br/>*(hoặc chạy `sync_env.bat`)* |
| `import_dashboard.py` | **1-Click Import Dashboard:** Nạp toàn bộ 9 Saved Objects (`.ndjson`) lên OpenSearch Dashboards (Wazuh Dashboard Port 443) qua REST API chỉ trong 1.5 giây. | `python scripts/import_dashboard.py` |
| `sigma_compiler.py` | **SigWaz Compiler Engine:** Biên dịch các quy tắc Sigma YAML thành cú pháp XML chuẩn của Wazuh, tự sinh luật ức chế phân cấp (`level="0"`), và kiểm tra chống lệch pha (`--check`). | `python scripts/sigma_compiler.py`<br/>`python scripts/sigma_compiler.py --check` |
