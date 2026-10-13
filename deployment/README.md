# 🚀 Deployment Configurations & Infrastructure Assets

Thư mục lưu trữ toàn bộ các tệp cấu hình triển khai, container compose, cấu hình agent và phân hệ phòng thủ mở rộng của hệ thống **Wazuh SOC Lab**.

---

## 🗂️ Cấu Trúc Thành Phần

| Thư Mục / Tệp Tin | Mô Tả Chức Năng |
| :--- | :--- |
| [`active-response/`](active-response/) | Kịch bản phản ứng chủ động tức thì trên Windows Endpoint (`kill-process.ps1`, `collect-evidence.ps1`). |
| [`dashboards/`](dashboards/) | Tệp cấu hình Saved Objects (`.ndjson`) nạp 1-Click Executive Incident Dashboard lên OpenSearch Dashboards (Port 443). |
| [`deception/`](deception/) | Mạng lưới bẫy mồi chủ động: Canary Honey-File SACL, Honey-Account tripwire, Network Decoy Port 21. |
| [`suricata/`](suricata/) | Cấu hình Suricata 8.0.7 NIDS, capture card mạng `ens33` và 4 Signatures thực chiến (`local.rules`). |
| `docker-compose.yml` | Khởi chạy cụm Wazuh All-in-One (Wazuh Manager, Indexer, Dashboard) trên Ubuntu Server. |
| `docker-compose-n8n.yml` | Khởi chạy container n8n Automation Engine tại cổng `5678`. |
| `ossec.conf` | Cấu hình trung tâm Wazuh Manager: định tuyến log, syscheck FIM, integration webhook n8n và Active Response. |
| `sysmon-config.xml` | Cấu hình Sysmon v15.2 (SwiftOnSecurity tối ưu) bắt trọn Process, Network, Memory và Registry telemetry. |

---

## ⚡ Lệnh Triển Khai Nhanh
* Khởi động cụm Wazuh SIEM:
  ```bash
  docker compose -f deployment/docker-compose.yml up -d
  ```
* Khởi động n8n SOAR Engine:
  ```bash
  docker compose -f deployment/docker-compose-n8n.yml up -d
  ```
