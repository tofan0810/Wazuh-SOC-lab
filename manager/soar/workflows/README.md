# 🤖 n8n SOAR Workflows

Thư mục lưu trữ 3 luồng công việc (workflows) chuẩn hóa của **n8n SOAR Engine** dưới dạng định dạng tệp JSON, sẵn sàng nạp (Import) trực tiếp vào giao diện web của n8n (`http://192.168.71.128:5678`).

---

## 📌 Danh Mục Workflows

| Tệp Cấu Hình | Tên Workflow | Mô Tả Chức Năng |
| :--- | :--- | :--- |
| `01_wazuh_soar_threat_enrichment.json` | **Workflow 1: Threat Enrichment & ChatOps Dispatcher** | Tiếp nhận Webhook alert từ Wazuh (`/webhook/wazuh-alert`), bóc tách IoC, truy vấn AbuseIPDB/VirusTotal, tạo HTML Card với các nút bấm inline và gửi về Telegram Bot. |
| `02_containment_action_executor.json` | **Workflow 2: Containment & Case Management Executor** | Lắng nghe callback khi Analyst bấm nút: thực thi diệt tiến trình (`Stop-Process`), cách ly host qua WinRM, hoàn tác giải phóng mạng (Rollback), và tạo Incident Ticket trên Jira Cloud REST API v3. |
| `03_scheduled_healthcheck_cron.json` | **Workflow 3: Scheduled Healthcheck Cron** | Tự động chạy định kỳ mỗi 6 giờ kiểm tra tính khả dụng của các máy ảo, dịch vụ Wazuh Manager và container Docker, gửi báo cáo tình trạng về Telegram. |

---

## ⚡ Hướng Dẫn Nạp Vào n8n (Import)
1. Truy cập giao diện n8n: `http://192.168.71.128:5678`
2. Chọn **Workflows** $\rightarrow$ **Add Workflow** $\rightarrow$ bấm biểu tượng ba chấm $\rightarrow$ chọn **Import from File**.
3. Chọn lần lượt từng file `.json` trên và bấm **Activate (Kích hoạt)**.
