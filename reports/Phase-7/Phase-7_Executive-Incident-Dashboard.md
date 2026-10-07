# BÁO CÁO TRIỂN KHAI EXECUTIVE INCIDENT DASHBOARD TRÊN WAZUH SIEM (PHASE 7)

* **Dự án:** Hệ thống Giám sát An ninh mạng & Ứng phó Sự cố Tập trung (Wazuh SIEM/XDR Lab)
* **Vị trí giả lập:** SOC Lead / Detection Engineer / SIEM Architect
* **Môi trường thực hiện:**
  * **Hạ tầng SIEM:** Wazuh Dashboard 4.14.5 / OpenSearch Dashboards 2.x (Port 443 - IP: `192.168.71.128`).
  * **Nguồn dữ liệu phân tích:** Chỉ mục `wazuh-alerts-*` lưu trữ telemetry máy trạm Windows 10 (`192.168.71.129`), Sysmon v15.2 và máy tấn công Kali Linux (`192.168.71.130`).
  * **Tệp cấu hình triển khai:** [`deployment/dashboards/soc_lab_executive_dashboard.ndjson`](../../deployment/dashboards/soc_lab_executive_dashboard.ndjson).
  * **Công cụ nạp tự động:** [`scripts/import_dashboard.py`](../../scripts/import_dashboard.py).

---
![Toàn cảnh giao diện Executive Incident Dashboard trên Wazuh](images/wazuh_dashboard_overview.png)

## I. MỤC TIÊU & GIÁ TRỊ VẬN HÀNH CỦA EXECUTIVE DASHBOARD

Trong một trung tâm điều hành an ninh mạng (Next-Gen SOC), việc chỉ đọc log sự cố dạng dòng lệnh (terminal) hoặc thông báo Telegram là chưa đủ đối với cấp quản lý (SOC Manager/CISO) và hội đồng đánh giá. Hệ thống cần một **Giao diện Giám sát Trung tâm (Single Pane of Glass)** có khả năng:
1. **Trực quan hóa tổng thể tình hình an ninh mạng:** Biến các dòng log JSON khô khan thành biểu đồ trực quan, dễ hiểu.
2. **May đo riêng cho bài toán thực chiến của phòng Lab:** Tập trung sâu vào 6 kỹ thuật tấn công trọng yếu (RDP Brute Force, Web LFI, và 4 giai đoạn MITRE Windows Kill Chain) thay vì hiển thị dữ liệu chung chung.
3. **Theo dõi chỉ số KPI vận hành theo thời gian thực:** Thống kê thời gian phản ứng phát hiện (MTTA < 3s) và thời gian tự động ngăn chặn (MTTR < 20s).
4. **Chuẩn hóa đóng gói mã nguồn (Saved Objects .ndjson):** Cho phép nạp tự động 1-click lên bất kỳ cụm Wazuh nào mà không cần cấu hình thủ công từng biểu đồ.

---

## II. BỐ CỤC 7 THÀNH PHẦN TRỰC QUAN HÓA (VISUALIZATION MATRIX)

Dashboard mang tên chính thức: **`SOC Lab - Executive Incident Overview`** gồm 7 thành phần chuyên biệt:

| STT | Tên Widget | Loại Biểu Đồ | Ý Nghĩa Giám Sát & Chỉ Số Kỹ Thuật |
| :---: | :--- | :---: | :--- |
| **1** | `Total Security Incidents KPI` | **Metric** | Đồng hồ đếm tổng số lượng sự cố an ninh trong lab, phân loại các mức độ nghiêm trọng và KPI phản ứng. |
| **2** | `Incident Severity Distribution` | **Donut Chart** | Tỷ lệ % phân bổ mức độ cảnh báo: Đỏ (Level 12 - Critical), Cam (Level 10 - High), Xanh (Level 3 - Info). |
| **3** | `MITRE ATT&CK Techniques Heatmap` | **Horizontal Bar** | Thống kê số lượng vi phạm theo 6 kỹ thuật lab: `T1110.001`, `T1190`, `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001`. |
| **4** | `Top Attacker Source IPs` | **Horizontal Bar** | Bảng xếp hạng IP tấn công hàng đầu (đứng đầu là máy tấn công Kali Linux `192.168.71.130`). |
| **5** | `Target Endpoints & Users` | **Data Table** | Thống kê máy trạm nạn nhân Windows 10 (`agent.name`) và tài khoản bị xâm hại (`testw`, `socrunner`). |
| **6** | `Malicious Processes Telemetry` | **Data Table** | Thống kê các file thực thi và tiến trình độc hại (`powershell.exe`, `fodhelper.exe`, `lsass.exe`, `httpd.exe`). |
| **7** | `Real-Time Security Incident Stream` | **Saved Search** | Bảng luồng sự cố trực tiếp: `timestamp`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre.id`, `data.srcip`, `agent.name`. |
