# CÁC KỊCH BẢN TẤN CÔNG & PHÁT HIỆN THỰC CHIẾN (PHASE 3)

## 🔹 KỊCH BẢN 2: T1210 - KHAI THÁC LỖ HỔNG ỨNG DỤNG WEB (LOCAL FILE INCLUSION - LFI)

Kịch bản này đóng vai trò chứng minh năng lực phân tích cú pháp ký tự lạ bằng biểu thức chính quy (**Regex**) và viết **Custom Decoders** tùy biến của một Kỹ sư Phát hiện (Detection Engineer).

### 1. Kỹ thuật giả lập tấn công (Attack Simulation)

* **Môi trường giả lập:** Một dịch vụ Web Server (ví dụ Apache) chạy trên cổng 80 của Endpoint.
* **Hành vi tấn công:** Hacker thực hiện gửi các Request chứa chuỗi ký tự duyệt ngược thư mục (Directory Traversal) độc hại nhằm đọc file cấu hình hệ thống qua trình duyệt hoặc công cụ `curl`:
```bash
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=../../../../etc/passwd"
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=..%2f..%2f..%2fboot.ini"

```



### 2. Thu thập Telemetry (Log Source)

* Toàn bộ hành vi được lưu lại trong tệp tin nhật ký truy cập ứng dụng Web. Ví dụ với tệp tin log của Apache: `/var/log/apache2/access.log`.
* Dòng log thô sinh ra có dạng cấu trúc chuẩn:
`192.168.71.130 - - [10/Jun/2026:22:10:05 +0700] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 400 450`

### 3. Kỹ thuật viết bộ tách chuỗi (Custom Decoders)

Mặc định Wazuh đã nhận diện được log Apache, nhưng để bóc tách sâu hơn tham số URL phục vụ cho việc phát hiện nâng cao, ta tiến hành cấu hình bổ sung vào file `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="web-access-lfi">
  <parent>web-accesslog</parent> <regex>GET (\S+page=\S+)\sHTTP</regex>
  <order>url_request</order>
</decoder>

```

### 4. Kỹ thuật viết Luật phát hiện tùy biến (Custom Rules Engineering)

Tiến hành nạp cấu hình bộ luật sử dụng mệnh đề đối khớp biểu thức chính quy (`pcre2`) để quét tìm dấu vết di chuyển thư mục độc hại độc lập trong file `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="web,attack,lfi,">
  <rule id="100002" level="10">
    <if_sid>31100</if_sid> <match>\.\./\.\./\.\./|\.\.%2f\.\.%2f|boot\.ini|etc/passwd</match>
    <description>CẢNH BÁO: Phát hiện hành vi khai thác lỗ hổng duyệt thư mục trái phép (LFI/Directory Traversal).</description>
    <mitre>
      <id>T1210</id>
    </mitre>
  </rule>
</group>

```

### 5. Kết quả kiểm chứng thực tế (Validation PoC)

* Khi đứng từ máy Kali Linux thực hiện gửi Request `curl` chứa các ký tự `../../../../etc/passwd`, hệ thống ngay lập tức ghi nhận hành vi.
* Truy cập giao diện quản trị **Wazuh Dashboard** $\rightarrow$ Vào mục **Threat Hunting** $\rightarrow$ Thiết lập bộ lọc thời gian `Last 15 minutes` và tìm kiếm từ khóa `passwd` hoặc mã `Rule ID: 100002`.
* Hệ thống hiển thị chi tiết dòng log bắt bài hành vi, bóc tách chính xác địa chỉ IP nguồn của Hacker và gắn cờ cảnh báo mức độ nguy hiểm cao (Level 10).
