# 🔌 Integrations & SOAR Extensions

Thư mục lưu trữ các module tích hợp bên thứ ba, mở rộng năng lực của **Wazuh SIEM** sang **Threat Intelligence** và **Điều phối phản ứng tự động hóa SOAR**.

---

## 🗂️ Cấu Trúc Các Phân Hệ

| Phân Hệ | Đường Dẫn | Chức Năng Chính |
| :--- | :--- | :--- |
| **n8n SOAR & Jira Cloud** | [`manager/soar/`](../manager/soar/) | Trung tâm điều phối SOAR: Tiếp nhận webhook alert từ Wazuh, làm giàu IoC qua AbuseIPDB/VirusTotal, phát thẻ cảnh báo ChatOps tương tác 2 chiều và quản lý sự cố trên Jira Cloud REST API v3. |
| **Telegram ChatOps** | [`telegram/`](telegram/) | Cầu nối cảnh báo thời gian thực về Telegram Bot (`@my_wazuh_soc_alert_bot`), định dạng HTML thẻ cảnh báo và hỗ trợ tương tác phản ứng. |
| **VirusTotal Threat Intel** | [`virustotal/`](virustotal/) | Cấu hình module `wazuh-integratord` đối soát mã băm tập tin (SHA256) từ FIM Syscheck với >70 Antivirus Cloud Engines, kích hoạt Rule 87105 khi phát hiện mã độc. |
