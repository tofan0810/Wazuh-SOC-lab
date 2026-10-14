# 📊 Wazuh SOC Lab - Executive Incident Overview Dashboard

> **Phân hệ:** Trụ Cột 3 - Xây Dựng Dashboard Chuyên Biệt Trên Wazuh SIEM  
> **Tương thích:** Wazuh Dashboard 4.14.5 / OpenSearch Dashboards 2.x (Port 443)  
> **Tệp cấu hình:** [`soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson)

---

## 📌 Tổng Quan

Mặc định sau khi cài đặt, Wazuh Dashboard chỉ cung cấp các màn hình giám sát chung chung (*Security Events, Integrity Monitoring, MITRE ATT&CK chung*). 

Tệp cấu hình [`soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson) là một **Custom Dashboard chuyên biệt** được thiết kế "may đo" riêng cho kịch bản phòng Lab của đồ án:
* **Tên Dashboard:** `SOC Lab - Executive Incident Overview`
* **Mục tiêu:** Trực quan hóa toàn bộ chuỗi đòn tấn công thực chiến (RDP Brute Force, Web LFI, và 4 stages MITRE Windows Kill Chain), làm nổi bật máy tấn công Kali Linux (`192.168.71.130`), máy trạm mục tiêu Windows 10 (`192.168.71.129`), và các chỉ số KPI vận hành SOC (MTTA < 3s, MTTR < 20s).

---

## 🎨 Bố Cục & 7 Thành Phần Trực Quan Hóa (7 Visualizations)

| Thành phần | Loại Widget | Đối tượng Dữ liệu & Ý nghĩa Giám sát |
| :--- | :---: | :--- |
| **1. Total Security Incidents KPI** | `Metric` | Đồng hồ đếm tổng số lượng sự cố an ninh được phát hiện trong Lab. |
| **2. Incident Severity Distribution** | `Donut Chart` | Tỷ lệ % phân bổ mức độ nghiêm trọng: Đỏ (Level 12 - Critical), Cam (Level 10 - High), Xanh (Level 3 - Info). |
| **3. MITRE ATT&CK Techniques Heatmap** | `Horizontal Bar` | Phân tích số lượng vi phạm theo 6 kỹ thuật tấn công thực chiến: `T1110.001`, `T1190`, `T1059.001`, `T1548.002`, `T1547.001`, `T1003.001` kèm Tactic tương ứng. |
| **4. Top Attacker Source IPs** | `Horizontal Bar` | Bảng xếp hạng IP phát động tấn công hàng đầu (đứng đầu là Kali Linux `192.168.71.130`). |
| **5. Target Endpoints & Compromised Users** | `Data Table` | Thống kê máy trạm nạn nhân Windows 10 (`agent.name`) và tài khoản bị nhắm mục tiêu (`testw`, `socrunner`). |
| **6. Malicious Processes Telemetry** | `Data Table` | Thống kê các file thực thi và tiến trình độc hại (`powershell.exe`, `fodhelper.exe`, `lsass.exe`, `httpd.exe`). |
| **7. Real-Time Security Incident Stream** | `Saved Search` | Bảng luồng sự cố theo thời gian thực: `timestamp`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre.id`, `data.srcip`, `agent.name`. |

---

## 🚀 Hướng Dẫn Nạp Dashboard (2 Cách)

### 🔹 Cách 1: Nạp 1-Click Tự Động Bằng Python CLI (Khuyến nghị)

Chạy script tự động hóa được tích hợp sẵn từ thư mục gốc của repository:

```powershell
python scripts/import_dashboard.py
```

* Script sẽ tự động đọc thông số từ file `.env` (hoặc cấu hình Docker), kết nối qua HTTPS port 443 của Wazuh Dashboard và nạp toàn bộ 9 Saved Objects chỉ trong **1.5 giây**.
* Khi thành công, script sẽ hiển thị thông báo xác nhận kèm đường link trực tiếp.

---

### 🔹 Cách 2: Nạp Thủ Công Qua Giao Diện Web OpenSearch Dashboards (GUI)

Nếu muốn thao tác trực tiếp trên trình duyệt Web:

1. Đăng nhập vào giao diện Wazuh Dashboard: **`https://192.168.71.128`** (Port 443).
2. Nhấp vào nút Menu 3 dấu gạch ngang (`≡`) ở góc trên bên trái.
3. Cuộn xuống nhóm **OpenSearch Dashboards** -> Chọn **Stack Management**.
4. Trong cột menu bên trái, nhấp vào **Saved Objects**.
5. Nhấp vào nút **Import** ở góc trên bên phải màn hình.
6. Kéo thả hoặc chọn tệp [`deployment/dashboards/soc_lab_executive_dashboard.ndjson`](soc_lab_executive_dashboard.ndjson).
7. Bật tùy chọn **Automatically overwrite all saved objects** (Tự động ghi đè nếu đã tồn tại) -> Bấm **Import**.
8. Bấm **Done** để hoàn tất.

---

## 🔗 Truy Cập Dashboard

Sau khi nạp thành công, bạn có thể truy cập ngay vào Dashboard qua:
* **Đường dẫn trực tiếp:** `https://192.168.71.128/app/dashboards#/view/soc-lab-executive-overview`
* **Hoặc từ Menu:** Bấm Menu `≡` -> Chọn **Dashboard** -> Nhấp vào **`SOC Lab - Executive Incident Overview`**.
