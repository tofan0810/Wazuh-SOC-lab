# Wazuh SIEM & Detection Engineering Lab

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)](https://attack.mitre.org/)

## 📝 Tổng quan Đồ án
Kho lưu trữ này chứa sơ đồ kiến trúc, các file cấu hình và chi tiết triển khai của **Hệ thống Giám sát An ninh mạng & Ứng phó Sự cố Tập trung** được xây dựng trên nền tảng **Wazuh SIEM/XDR**. Được thiết kế nhằm giả lập môi trường vận hành thực tế của một doanh nghiệp, đồ án này tập trung sâu vào việc thu thập log, tự viết luật phát hiện tấn công (**Detection Engineering**) chuẩn hóa theo framework **MITRE ATT&CK**, tự động hóa phòng thủ (**Active Response**) và kích hoạt cảnh báo theo thời gian thực.

### Mục tiêu Cốt lõi:
*   Triển khai hạ tầng SIEM/XDR hoạt động ổn định sử dụng mã nguồn mở.
*   Cấu hình kiểm toán chuyên sâu trên máy trạm (Endpoint Auditing) thông qua **Windows Sysmon** và log hệ thống.
*   Xây dựng **Custom Decoders và Rules (Luật tự viết)** để phát hiện các kỹ thuật tấn công tinh vi.
*   Triển khai cơ chế phòng thủ chủ động **Active Response** để tự động ngăn chặn các mối đe dọa đang diễn ra.
*   Tích hợp hệ thống cảnh báo thời gian thực về kênh giám sát tập trung (Telegram/Discord).

---

## 🏗️ Kiến trúc & Thiết lập Lab

### Sơ đồ Luồng dữ liệu và Mạng (Topology)
```text
  [ Kali Linux (Máy tấn công) ] --(Tấn công)--> [ Windows 10 (Máy nạn nhân) ]
                                                            │
                                                    (Sysmon / Event Logs)
                                                            │
                                                            ▼
                                                   [ Wazuh Agent ]
                                                            │
                                                   (Đẩy log mã hóa)
                                                            │
                                                            ▼
                                            [ Ubuntu Server (Wazuh Manager) ]
                                               ├── Wazuh Indexer (Lưu trữ log)
                                               └── Wazuh Dashboard (Giao diện Web)
                                                            │
                                                   (Kích hoạt Cảnh báo)
                                                            │
                                                            ▼
                                                 [ Bot Telegram/Discord ]

```

> 💡 *Mẹo: Bạn có thể thay thế khối văn bản này bằng hình ảnh sơ đồ mạng vẽ từ Draw.io/Figma và lưu tại thư mục `architecture/topology.png`.*

### Thông số kỹ thuật các thành phần:

1. **Wazuh Manager (Chạy trên Ubuntu Server):** Đóng vai trò trung tâm chịu trách nhiệm biên dịch log (decode), đối khớp rule, kích hoạt alert và phát lệnh ứng phó tự động.
2. **Giám sát Endpoint (Máy Windows 10):** Được cài đặt **Wazuh Agent** phối hợp cùng **Microsoft Sysmon** (sử dụng file cấu hình bảo mật nâng cao) nhằm bắt trọn các hành vi ở tầng nhân (kernel) và tiến trình hệ thống.
3. **Nền tảng Tấn công (Máy Kali Linux):** Sử dụng để giả lập các kỹ thuật tấn công của tin tặc hướng vào máy Windows 10 nhằm sinh log kiểm thử.

---

## 🗂️ Cấu trúc Thư mục Repo

```text
wazuh-soc-lab/
│
├── README.md               # Tài liệu chính: Sơ đồ, cách dựng, kết quả (Quan trọng nhất)
├── documents/              # Tài liệu lý thuyết
│
├── architecture/           # Chứa ảnh sơ đồ mạng, sơ đồ luồng log (vẽ bằng Draw.io/Figma)
│
├── deployment/             # Hướng dẫn hoặc script cài đặt
│   ├── docker-compose.yml  # (Nếu bạn dựng Wazuh bằng Docker)
│   └── sysmon-config.xml   # File cấu hình Sysmon tối ưu (như SwiftOnSecurity) bạn nạp vào máy Windows
│
├── custom-rules/           # NƠI KHOE TRÌNH ĐỘ: Chứa các rule XML do bạn tự viết
│   ├── web-lfi-detection.xml
│   ├── ssh-brute-force-active-response.xml
│   └── sysmon-powershell-rules.xml
│
├── integrations/           # Code tích hợp gửi alert
│   └── ossec-slack-telegram.js / python # Script đẩy cảnh báo về Telegram/Discord
│
└── reports/                # File PDF báo cáo một case study điều tra cụ thể từ Lab này
```

---

## 🚀 Kịch bản Tấn công & Phát hiện Thực chiến (Key Use Cases)

### 🔹 Kịch bản 1: T1110 - Phát hiện Tấn công Brute Force & Tự động khóa IP (Active Response)

* **Hành vi của lực lượng tấn công:** Sử dụng công cụ `Hydra` từ máy Kali Linux để thực hiện quét dò mật khẩu tốc độ cao qua giao thức RDP/SSH hướng vào máy mục tiêu.
* **Thu thập Telemetry (Log):** Theo dõi log đăng nhập hệ thống hệ điều hành (Windows Event ID 4625 - Đăng nhập thất bại).
* **Chiến lược phát hiện:** Xây dựng một quy tắc (Rule) tự thiết kế nhằm phát hiện hành vi đăng nhập sai liên tiếp vượt ngưỡng cấu hình từ cùng một địa chỉ IP nguồn trong cửa sổ thời gian $10$ giây.
* **Phản ứng giảm thiểu (Active Response):** Kích hoạt script tường lửa tự động trên hệ thống quản lý để chặn (Drop) toàn bộ các gói tin đến từ IP của máy Kali Linux trong vòng $600$ giây ($10$ phút).
* **Minh chứng thực tế (PoC):**
> *[Chèn ảnh chụp giao diện Wazuh Dashboard hiển thị Rule được kích hoạt & Active Response thực thi thành công]*



### 🔹 Kịch bản 2: T1210 - Khai thác Lỗ hổng Ứng dụng Web (Local File Inclusion - LFI)

* **Hành vi của lực lượng tấn công:** Thực hiện kỹ thuật duyệt thư mục (Directory Traversal) và tấn công LFI hướng vào một dịch vụ Web Server giả lập đang chạy trên máy mục tiêu, hòng đọc các file hệ thống nhạy cảm (như `..\..\boot.ini` hoặc các file cấu hình).
* **Thu thập Telemetry (Log):** Cấu hình Wazuh thu thập và đọc log truy cập (Access Log) của dịch vụ Web (Apache/Nginx/IIS).
* **Chiến lược phát hiện:** Tự thiết kế các bộ **Custom Decoders** và **Rules** sử dụng biểu thức chính quy (`Regex`) để bóc tách trường URI, nhận diện các chuỗi ký tự độc hại đặc trưng (`..%2f`, `%00`, `boot.ini`). Đẩy mức độ nghiêm trọng của cảnh báo lên Level 10 (Mức cao).
* **Minh chứng thực tế (PoC):**
> *[Chèn ảnh chụp mục Security Events trên Wazuh hiển thị chính xác chuỗi URI bị bắt bài và gắn cờ cảnh báo]*



### 🔹 Kịch bản 3: T1059.001 - Phát hiện Thực thi PowerShell Độc hại & Giám sát Tiến trình

* **Hành vi của lực lượng tấn công:** Khởi chạy một đoạn script PowerShell đã bị mã hóa (Obfuscated) nhằm thực hiện hành vi dump bộ nhớ LSASS lấy thông tin tài khoản hoặc dò tìm thông tin nội bộ (Sử dụng các tham số ẩn danh như Base64).
* **Thu thập Telemetry (Log):** Sử dụng log nâng cao từ **Windows Sysmon Event ID 1 (Khởi tạo tiến trình - Process Creation)** và **Event ID 7 (Tải phân hệ - Image Loaded)**.
* **Chiến lược phát hiện:** Cấu hình bộ luật đối khớp trực tiếp với các tham số dòng lệnh nguy hiểm của PowerShell (ví dụ: `-EncodedCommand`, `-WindowStyle Hidden`, `-NoP`).
* **Minh chứng thực tế (PoC):**
> *[Chèn ảnh chụp chi tiết log Sysmon phân tích được tiến trình cha và hệ thống Wazuh gắn cờ cảnh báo câu lệnh mã hóa]*



---

## 🤖 Tích hợp SOAR: Hệ thống Cảnh báo qua Kênh Chat (ChatOps)

Để tối ưu hóa thời gian xử lý và giảm thiểu tình trạng quá tải cảnh báo (Alert Fatigue), lab này được tích hợp một script webhook tùy biến đặt tại (`integrations/wazuh-telegram-alert.py`).

Bất cứ khi nào hệ thống xuất hiện một cảnh báo có **Mức độ nghiêm trọng (Severity Level) $\ge$ 10**, Wazuh Manager sẽ chuyển tiếp siêu dữ liệu JSON của alert đó sang script Python để định dạng lại và đẩy ngay một thông báo khẩn cấp về kênh chat SOC chuyên dụng.

### Biểu mẫu Cảnh báo trực quan:

```json
⚠️ [SOC ALERT] PHÁT HIỆN SỰ CỐ AN NINH NGHIÊM TRỌNG
● Rule ID: 100201 (Custom LFI Detection)
● Mức độ nghiêm trọng: 10 (High)
● Máy trạm: Windows10-User (002)
● IP Tấn công: 192.168.X.X
● Mô tả chi tiết: Phát hiện hành vi nghi vấn tấn công Local File Inclusion trên URI mục tiêu.

```

> *[Chèn ảnh chụp màn hình tin nhắn thông báo thực tế nhận được trên Telegram hoặc Discord]*

---

## 🛠️ Hướng dẫn Cài đặt & Triển khai

### 1. Điều kiện tiên quyết

* Phần mềm máy ảo: VMware Workstation hoặc VirtualBox.
* Tài nguyên phần cứng khuyến nghị: Cấp tối thiểu 8GB RAM cho máy ảo Ubuntu Server (chạy cụm Wazuh Stack) và 2GB RAM cho máy Windows 10.

### 2. Triển khai hạ tầng cụm Wazuh Stack

```bash
# Clone source code của đồ án về máy
git clone [https://github.com/tofan0810/Wazuh-SOC-lab](https://github.com/tofan0810/Wazuh-SOC-lab)
cd Wazuh-SOC-lab/deployment

# Khởi chạy cụm hệ thống SIEM bằng Docker Compose
docker-compose up -d
```

### 3. Cấu hình trên Máy trạm mục tiêu

* Tải và cài đặt Wazuh Agent lên máy Windows 10, trỏ cấu hình địa chỉ IP về máy Ubuntu (Wazuh Manager).
* **Cấu hình nâng cao cho Windows:** Cài đặt Microsoft Sysmon bằng file cấu hình đi kèm trong bộ source code:

```cmd
    sysmon.exe -i sysmon-config.xml
```
*   **Cập nhật Luật phát hiện tự viết:** Sao chép toàn bộ các file trong thư mục `custom-rules/` thả vào đường dẫn `/var/ossec/etc/rules/` trên máy Ubuntu Manager, sau đó tiến hành restart lại dịch vụ wazuh-manager.

---

## 📊 Kỹ năng Thực tế Đạt được qua Đồ án này
*   **Quản trị và Vận hành SIEM/XDR:** Nắm vững kiến trúc hệ thống, cài đặt phân hệ Agent, tối ưu hóa nguồn log nạp vào.
*   **Kỹ nghệ Phát hiện Tấn công (Detection Engineering):** Thành thạo kỹ năng viết luật bằng cấu trúc XML, thiết kế bộ lọc decoder, sử dụng biểu thức chính quy (Regex) và tư duy tối ưu giảm thiểu cảnh báo giả (False-Positive).
*   **Phân tích Telemetry Máy trạm (Endpoint):** Hiểu sâu sắc cơ chế ghi log hệ thống Windows Event Logs, cấu trúc bảng dữ liệu của Sysmon nâng cao.
*   **Tự động hóa & Ứng phó Sự cố:** Kích hoạt kịch bản cô lập chủ động thông qua Active Response và cấu hình luồng dữ liệu tự động hóa thông báo (Webhook Notification Flows).
