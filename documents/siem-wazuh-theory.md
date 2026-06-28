# GIẢI PHÁP **SIEM** VÀ KIẾN TRÚC **WAZUH**

## PHẦN 1: TỔNG QUAN VỀ GIẢI PHÁP SIEM

### 1. Định nghĩa và Ý nghĩa thuật ngữ

**SIEM** là viết tắt của **Security Information and Event Management** (Quản lý Sự kiện và Thông tin An ninh mạng).

* **S**ecurity: Bảo mật / An ninh mạng.
* **I**nformation: Thông tin.
* **E**vent: Sự kiện.
* **M**anagement: Quản lý.

> **Điểm khác biệt cốt lõi:** Nếu như `Syslog` thuần túy chỉ là giải pháp lưu trữ các thông tin vận hành (log), thì **SIEM vượt trội hơn nhờ vào khả năng Phân tích dữ liệu (Data Analysis)** để phát hiện các mối đe dọa.

### 2. Các thành phần và Luồng xử lý dữ liệu chung của SIEM

Một giải pháp SIEM tiêu chuẩn sẽ xử lý dữ liệu qua 5 giai đoạn cốt lõi sau:

```
[Data Collection] ──> [Data Ingestion] ──> [Data Parsing] ──> [Data Analysis] ──> [Visualization & Alerting]

```

#### **Giai đoạn 1: Thu thập dữ liệu (Data Collection)**
* Thu thập tất cả thông tin liên quan đến Cyber Security từ mọi ngóc ngách trong doanh nghiệp: Thiết bị phần cứng, hệ điều hành, middleware, database, API, môi trường Cloud (Public, Private, Hybrid), cho đến các dịch vụ SaaS (Office 365, GitHub...).
* Tích hợp sâu với các giải pháp bảo mật khác: Antivirus, WAF, PAM/PIM, DLP, Endpoint Protection, Threat Intelligence, Identity Protection, SOAR, SOC... nhằm tạo ra cái nhìn toàn diện nhất.


#### **Giai đoạn 2: Tiếp nhận dữ liệu (Data Ingestion)**
* Dữ liệu sau khi thu thập được gửi liên tục và tập trung về hệ thống ghi nhận để chuẩn bị cho các bước xử lý tiếp theo.


#### **Giai đoạn 3: Chuẩn hóa dữ liệu (Data Parsing / Data Recording)**
* Biến đổi dữ liệu thô (raw log) từ nhiều nguồn, nhiều định dạng khác nhau thành một **định dạng thống nhất duy nhất**.
* Mục đích: Loại bỏ sự không nhất quán, giúp việc quản lý, phân tích và lưu trữ đạt hiệu quả tối ưu.


#### **Giai đoạn 4: Phân tích dữ liệu (Data Analysis) - "Trái tim" của SIEM**
* Sàng lọc, xem xét kỹ lưỡng dữ liệu đã chuẩn hóa để tìm ra các hành vi bất thường hoặc dấu hiệu tấn công (Cyber Attack).
* Sử dụng các kỹ thuật nâng cao: *Behavior Analysis* (Phân tích hành vi), *Anomaly Detection* (Phát hiện thực thể bất thường), *Integrity Verification* (Xác thực tính toàn vẹn), và ứng dụng *AI/Machine Learning* để dự đoán, ngăn chặn sớm các cuộc tấn công tinh vi.


#### **Giai đoạn 5: Trực quan hóa & Cảnh báo (Visualization & Alerting)**
* Chuyển kết quả phân tích phức tạp thành giao diện trực quan thông qua các Dashboard, báo cáo chi tiết (Reports) và hệ thống cảnh báo linh hoạt (Alerts).
* Giúp các nhà quản trị và chuyên gia SOC/Bảo mật nhanh chóng phản ứng và điều chỉnh chiến lược phòng thủ.



---

## PHẦN 2: KIẾN TRÚC TỔNG QUAN CỦA WAZUH

Wazuh là một nền tảng bảo mật mã nguồn mở được xây dựng dựa trên kiến trúc module linh hoạt, bao gồm các thành phần chính sau:

### 1. Wazuh Agent (Thành phần Thu thập)

* **Vị trí:** Được cài đặt trực tiếp trên các endpoint cần giám sát (Windows, Linux, macOS, các môi trường Cloud hoặc thiết bị hạ tầng IT).
* **Chức năng:** Thu thập dữ liệu trạng thái an ninh mạng từ máy chủ/ứng dụng, **mã hóa dữ liệu** này và gửi an toàn về cho Wazuh Manager.

### 2. Wazuh Manager (Bộ não Trung tâm)

* **Chức năng:** Tiếp nhận, ghi nhận và phân tích các sự kiện an toàn thông tin từ Agent gửi về nhằm phát hiện dấu hiệu đe dọa, đồng thời điều phối các phản ứng phòng thủ (Cyber Kill Chain).
* **Khả năng mở rộng:** Hỗ trợ tính năng **Clustering (Cluster các Worker Nodes)**, cho phép thêm/bớt các node linh hoạt để xử lý lượng log khổng lồ từ các hệ thống quy mô lớn mà không bị nghẽn.

### 3. Wazuh Indexer (Kho lưu trữ & Tra cứu)

* **Chức năng:** Lưu trữ, đánh chỉ mục (indexing) và hỗ trợ tìm kiếm siêu tốc các dữ liệu đã qua xử lý.
* **Hiệu suất & An toàn:** Cho phép cấu hình Multi-node để tối ưu hóa truy vấn, tăng tốc độ tìm kiếm và đảm bảo tính toàn vẹn của dữ liệu thông qua cơ chế sao chép dữ liệu (**Data Replication**).

### 4. Wazuh Dashboard (Giao diện Trực quan)

* **Chức năng:** Cung cấp giao diện đồ họa (GUI) cho người dùng để trực quan hóa toàn bộ dữ liệu log, quản lý các cảnh báo, xuất báo cáo và theo dõi mức độ tuân thủ các tiêu chuẩn bảo mật.
* **Mở rộng:** Cung cấp nhiều add-on và plugin hữu ích giúp tối ưu hóa quy trình vận hành cho các chuyên gia phân tích cú pháp và xử lý sự cố.

---

## TỔNG KẾT BÀI HỌC

* **SIEM** là một quy trình khép kín từ khâu **Thu thập -> Chuẩn hóa -> Phân tích hành vi nâng cao -> Cảnh báo trực quan**.
* **Wazuh** hiện thực hóa mô hình SIEM này bằng kiến trúc phân tán: **Agent** (Thu thập) $\rightarrow$ **Manager** (Phân tích/Điều phối) $\rightarrow$ **Indexer** (Lưu trữ/Chỉ mục) $\rightarrow$ **Dashboard** (Trực quan hóa). Nhờ kiến trúc module và khả năng clustering, Wazuh có thể mở rộng vô hạn và dễ dàng tích hợp với hệ sinh thái bảo mật của doanh nghiệp.