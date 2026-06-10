# NỘI DUNG ĐỒ ÁN

## 1. Mô tả kỹ lại Ý tưởng & Phạm vi Đồ án (Scope)

Đồ án này sẽ đóng vai trò là **Hạ tầng Giám sát An ninh mạng tập trung** giả lập cho một doanh nghiệp nhỏ. Mục tiêu là chứng minh bạn biết cấu hình nguồn log, biết lọc nhiễu, biết viết rule để bắt các kỹ thuật tấn công phổ biến, và biết đẩy cảnh báo về kênh chat.

### 🏗️ Kiến trúc mô hình Lab (Bố trí trên máy ảo của bạn)

Bạn không cần quá nhiều máy ảo để làm nóng máy, cấu hình tối thiểu chỉ cần:

1. **Máy ảo 1 (Ubuntu Server):** Cài đặt **Wazuh Manager + Indexer + Dashboard** (Đóng vai trò là trung tâm xử lý log).
2. **Máy ảo 2 (Windows 10/11 Client hoặc Windows Server):** Cài **Wazuh Agent + Sysmon**. Đây sẽ là máy nạn nhân bị giám sát.
3. **Máy ảo 3 (Kali Linux):** Máy của bạn đóng vai trò là Attacker để thực hiện các hành vi tấn công nhằm sinh ra log.

---

## 2. Các "Key Use Cases" (Các kịch bản bạn sẽ làm để khoe trong CV)

Thay vì chỉ cài đặt xong để đó, bạn sẽ thực hiện và lưu lại cấu hình của 3 kịch bản thực chiến sau trong repo:

* **Kịch bản 1: Phát hiện tấn công Brute Force SSH / RDP**
* *Tấn công:* Dùng Hydra từ Kali Linux để quét mật khẩu máy Windows/Ubuntu.
* *Phòng thủ:* Cấu hình Wazuh phát hiện hành vi đăng nhập sai liên tục trong thời gian ngắn $\rightarrow$ Kích hoạt tính năng **Active Response** để tự động khóa IP của máy Kali trong 10 phút.


* **Kịch bản 2: Phát hiện quét lỗ hổng Web (ví dụ Local File Inclusion - LFI)**
* *Tấn công:* Dùng các công cụ scan hoặc kích hoạt các chuỗi payload LFI (`/etc/passwd`, `..%2f..%2f`) lên một web server giả lập.
* *Phòng thủ:* Viết **Custom Decoder/Rule** trong Wazuh để phân tích log truy cập (Access Log) của Apache/Nginx, bóc tách các ký tự lạ và nâng mức cảnh báo lên Level 10 (High Severity).


* **Kịch bản 3: Giám sát hành vi bất thường của Tiến trình (Endpoint Detection)**
* *Tấn công:* Chạy một script PowerShell đã bị mã hóa (Obfuscated) hoặc cố tình dump bộ nhớ LSASS bằng công cụ giả lập.
* *Phòng thủ:* Tận dụng log nâng cao từ **Sysmon**, viết rule Wazuh để bắt các Event ID cụ thể (như Event ID 1: Process Creation có chứa các cờ chạy ngầm nguy hiểm).



---

## 3. Cấu trúc thư mục chuẩn cho Repo GitHub

Một repo lộn xộn sẽ làm mất điểm. Bạn nên tổ chức thư mục như một kỹ sư thực thụ:

```text
wazuh-soc-lab/
│
├── README.md               # Tài liệu chính: Sơ đồ, cách dựng, kết quả (Quan trọng nhất)
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
