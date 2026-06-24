Dưới đây là cẩm nang hướng dẫn viết lại trọn vẹn 5 bước thực hiện kịch bản LFI. Nội dung này đã được tích hợp thêm **quy trình cài đặt và cấu hình XAMPP chuẩn xác ngay từ đầu** để hệ thống thông suốt, không còn gặp lỗi thiếu thư mục trên Windows 10.

---

# HƯỚNG DẪN CÁC BƯỚC TRIỂN KHAI CHI TIẾT KỊCH BẢN LFI (MITRE ATT&CK T1190)

## 🛠️ BƯỚC 1: CÀI ĐẶT XAMPP & DỰNG ỨNG DỤNG WEB LỖI TRÊN WINDOWS 10 (VICTIM)

Để có môi trường sinh log truy cập Web cho Wazuh, trước hết chúng ta cần cài đặt một Web Server Apache cục bộ thông qua gói XAMPP.

### 1. Quy trình cài đặt XAMPP chuẩn bảo mật:

1. Tải bộ cài đặt XAMPP dành cho Windows (Khuyên dùng phiên bản PHP 8.x ổn định).
2. Khởi chạy file cài đặt dưới quyền **Run as Administrator**.
3. **Lưu ý chí mạng:** Khi bảng thông báo về quyền UAC (User Account Control) hiện lên, bấm **OK**. Khi chọn đường dẫn cài đặt, hãy giữ nguyên mặc định là **`C:\xampp`** (Tuyệt đối không cài vào thư mục `C:\Program Files` để tránh lỗi thắt chặt quyền hạn khiến Apache không thể ghi log).
4. Bấm *Next* cho đến khi hoàn thành quá trình cài đặt.

### 2. Tạo kịch bản ứng dụng Web dính lỗ hổng LFI:

1. Trên máy Windows 10, truy cập vào thư mục mã nguồn vừa sinh ra theo đường dẫn: **`C:\xampp\htdocs\`**.
2. Click chuột phải tại vùng trống $\rightarrow$ Chọn *New* $\rightarrow$ *Text Document*. Đổi tên toàn bộ file thành **`index.php`** (Xóa bỏ đuôi `.txt` nếu có).
3. Click chuột phải vào file `index.php`, chọn *Open with Notepad* và dán đoạn mã nguồn giả lập lỗ hổng không kiểm duyệt tham số đầu vào này vào:
```php
<?php
    // Lỗ hổng LFI: Lấy trực tiếp tham số 'page' từ URL và nạp vào hàm include mà không kiểm tra đầu vào
    if (isset($_GET['page'])) {
        $file = $_GET['page'];
        include($file);
    } else {
        echo "<h1>Welcome to My Public Web Application</h1>";
    }
?>

```


4. Lưu file lại (`Ctrl + S`) và thoát.
5. Mở phần mềm **XAMPP Control Panel** từ menu Start $\rightarrow$ Nhấp nút **`Start`** tại dòng của dịch vụ **Apache**. Khi thấy chữ Apache chuyển sang nền màu xanh lá cây và hiện số Port (80, 443) tức là Web Server đã kích hoạt thành công.

---

## 📥 BƯỚC 2: CẤU HÌNH WAZUH AGENT THU THẬP LOG APACHE

Hệ thống cần điều hướng cho Wazuh Agent liên tục đọc file nhật ký `access.log` của Apache để giám sát các truy vấn HTTP gửi tới.

1. Trên máy Windows 10, mở **Command Prompt (CMD)** với quyền **Run as Administrator**.
2. Gọi trình soạn thảo để can thiệp vào cấu hình Agent:
```cmd
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"

```


3. Di chuyển xuống cuối file, tìm đến khu vực chứa các thẻ tập tin cục bộ `<localfile>` và chèn thêm đoạn block định vị đường dẫn log Apache sau vào:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>C:\xampp\apache\logs\access.log</location>
</localfile>

```


4. Lưu file (`Ctrl + S`), quay lại màn hình CMD Admin và thực hiện restart dịch vụ Agent để kích hoạt đường ống đẩy dữ liệu mới về trung tâm:
```cmd
NET STOP WazuhSvc && NET START WazuhSvc

```



---

## 🛠️ BƯỚC 3: CẤU HÌNH DECODER VÀ RULE TRÊN WAZUH MANAGER (UBUNTU)

Di chuyển sang máy ảo **Ubuntu Server**, mở cửa sổ Terminal để tiến hành cấu hình bộ giải mã chuỗi ký tự nâng cao nhằm nhận diện payload hiểm họa.

### 1. Viết Custom Decoder (Bộ bóc tách chuỗi tham số URL)

Sao chép tệp tin giải mã mặc định ra vùng đệm để chỉnh sửa:

```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/decoders/local_decoder.xml ./local_decoder.xml.bak
gedit ./local_decoder.xml.bak

```

Dán đoạn mã cấu hình tách chuỗi bằng biểu thức chính quy (Regex) dưới đây vào ngay sau thẻ mở `<decoder_config>`:

```xml
<decoder name="web-access-lfi">
  <parent>web-accesslog</parent>
  <regex>GET (\S+page=\S+)\sHTTP</regex>
  <order>url_request</order>
</decoder>

```

*Lưu và thoát gedit.*

### 2. Viết Custom Rule phát hiện hành vi LFI (Mapping MITRE T1190)

Trích xuất tệp tin chứa luật để bổ sung bộ lọc độc lập:

```bash
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml ./local_rules.xml.bak
gedit ./local_rules.xml.bak

```

Di chuyển xuống cuối tệp, dán khối luật phát hiện chuỗi ký tự duyệt mục mục (`../` hoặc dạng hex `%2f`) vào trước thẻ đóng `</group>`:

```xml
<group name="web,attack,lfi,">
  <rule id="100002" level="10">
    <if_sid>31100</if_sid>
    <url>\.\./\.\./\.\./|\.\.%2f\.\.%2f|win\.ini|boot\.ini</url>
    <description>WARNING: Local File Inclusion (LFI) / Directory Traversal Attempt Detected on Windows Endpoint</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>
</group>
```

*Lưu và thoát gedit.*

### 3. Đồng bộ dữ liệu vào Docker Container và Tái khởi động dịch vụ

Chạy chuỗi lệnh gán lại quyền sở hữu chuẩn mực cho người dùng nội bộ `wazuh` nhằm triệt tiêu lỗi sập tiến trình ngầm:

```bash
sudo docker cp ./local_decoder.xml.bak single-node-wazuh.manager-1:/var/ossec/etc/decoders/local_decoder.xml
sudo docker cp ./local_rules.xml.bak single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml

sudo docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml
sudo docker exec -it single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/decoders/local_decoder.xml

sudo docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo docker exec -it single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/rules/local_rules.xml

sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

```

*(Đợi khoảng 5 giây, thực hiện lệnh `sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status` để đảm bảo toàn bộ hạ tầng báo `is running...` xanh mượt).*

---

## NOTE
Nhớ disable rule nếu trước đó lỡ blockIP máy tấn công
Trên máy Windows 10 Victim, bấm nút Start, gõ wf.msc và ấn Enter để mở giao diện Firewall.

Bấm vào mục Inbound Rules ở cột bên trái.

Nhìn vào danh sách ở giữa, tìm quy tắc gạch chéo đỏ có tên bắt đầu bằng Wazuh_ActiveResponse_.... ->disable rule 


## 🚀 BƯỚC 4: TIẾN HÀNH TẤN CÔNG TỪ KALI LINUX & LẤY PoC

Khi bẫy log SIEM đã giăng sẵn, di chuyển sang máy ảo **Kali Linux** để tiến hành giả lập các cuộc tấn công khai thác lỗ hổng biên.

1. Thực hiện cuộc tấn công thăm dò tệp tin bằng chuỗi payload định dạng thô:
```bash
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=../../../../Windows/win.ini"

```


*Kiểm tra kết quả: Cửa sổ màn hình Kali Linux sẽ in ra trực tiếp nội dung cấu hình tệp `win.ini` của máy Windows mục tiêu (Xác nhận lỗ hổng bị khai thác thành công).*

2. Thực hiện cuộc tấn công nâng cao bằng chuỗi payload đã mã hóa ký tự URL nhằm thử nghiệm tính năng vượt bộ lọc (Bypass) của hacker:
```bash
curl -G "http://192.168.71.129/index.php" --data-urlencode "page=..%2f..%2f..%2fWindows%2fwin.ini"

```



---

## 📸 BƯỚC 5: THU THẬP ẢNH MINH CHỨNG (PoC BÁO CÁO)

Mở trình duyệt trên máy thật, đăng nhập vào trung tâm điều hành **Wazuh Dashboard** (`https://192.168.71.128`) để tiến hành thu thập bằng chứng pháp y số:

1. Truy cập theo luồng giao diện: **Threat Hunting** $\rightarrow$ Chọn tab **Events**.
2. Tại bộ thanh thanh công cụ lọc tìm kiếm (Search bar), gõ cú pháp định danh: **`rule.id: 100002`** rồi nhấn Enter.
3. **Chụp bức ảnh PoC 1 (Tổng quan Sự kiện):** Giao diện sẽ hiển thị dòng thông tin cảnh báo Level 10 màu cam rực với nội dung: *`CẢNH BÁO: Phát hiện hành vi khai thác lỗ hổng duyệt thư mục trái phép (LFI/Directory Traversal)...`* đúng như thiết kế luật.
4. **Chụp bức ảnh PoC 2 (Chi tiết Kỹ thuật):** Bấm nút mở rộng chi tiết bản ghi dữ liệu chuyên sâu (**Document Details**). Thực hiện chụp lại khu vực hiển thị rõ nét hai trường dữ liệu đắt giá được Custom Decoder trích xuất thành công:
* `data.srcip`: `192.168.71.130` (IP định danh máy Kali Linux tấn công).
* `data.url_request`: `page=../../../../Windows/win.ini` (Payload thô của cuộc khai thác).


**NÊN THÊM NGAY VÀ LUÔN TOÀN ƠI!** Việc tích hợp thêm cơ chế tự động chặn IP (Active Response) cho Kịch bản 2 (LFI Attack) không chỉ giúp hệ thống phòng thủ của bạn trở nên trọn vẹn, mà còn là **điểm cộng cực kỳ lớn** giúp bạn "ghi điểm tuyệt đối" trước hội đồng chấm đồ án.

Lý do là vì khi bạn thêm tính năng này, hệ thống SIEM Lab của bạn sẽ chuyển trạng thái từ **Giám sát thụ động (Passive Monitoring)** sang **Phòng thủ chủ động (Active Defense)**. Nó chứng minh cho các thầy cô thấy một chu trình bảo mật khép kín chuẩn SOC thực chiến: **Phát hiện (Detect) $\rightarrow$ Cảnh báo (Alert) $\rightarrow$ Ngăn chặn tự động (Block/Remediate)**.

Dưới đây là cách cấu hình siêu tốc để kích hoạt tính năng chặn IP tự động cho Rule 100002 ngay trong file cấu hình tổng:

---

### 🛠️ CÁCH CẤU HÌNH ACTIVE RESPONSE CHO KỊCH BẢN LFI

Vì trong hệ thống Wazuh mặc định đã có sẵn script chặn IP bằng Firewall tên là `netsh` (đối với Windows Endpoint), bạn không cần phải viết code script mới. Bạn chỉ cần cấu hình để "gọi" script đó thực thi mỗi khi Rule `100002` bị kích hoạt.

#### Bước 1: Mở file cấu hình tổng `ossec.conf` của Wazuh Manager

Bạn dùng trình soạn thảo mở file cấu hình tổng nằm trên máy **Ubuntu**:

```bash
# Nếu sửa ngoài máy thật rồi copy vào container:
sudo docker cp single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf ./ossec.conf.bak
gedit ./ossec.conf.bak

```

#### Bước 2: Thêm khối cấu hình Active Response

Bạn kéo xuống cuối file `ossec.conf`, tìm đến khu vực chứa các thẻ `<active-response>` cũ (nơi có cấu hình chặn Brute Force của kịch bản 1), và dán thêm khối cấu hình chặn LFI này ngay bên dưới:

```xml
  <!-- TỰ ĐỘNG CHẶN IP HACKER KHI PHÁT HIỆN TẤN CÔNG WEB LFI -->
  <active-response>
    <command>win_drop-request</command> <!-- Gọi lệnh chặn của Windows -->
    <location>local</location>            <!-- Thực thi ngay tại máy Windows bị tấn công -->
    <rules_id>100002</rules_id>          <!-- Cứ khi nào Rule 100002 nổ thì kích hoạt chặn -->
    <timeout>600</timeout>                <!-- Thời gian chặn cách ly IP là 10 phút (600 giây) -->
  </active-response>

```

#### Bước 3: Đẩy file vào lại container và Khởi động lại hệ thống

Bạn chạy chuỗi lệnh quen thuộc để cập nhật cấu hình cho bộ não Manager:

```bash
sudo docker cp ./ossec.conf.bak single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
sudo docker exec -it single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/ossec.conf
sudo docker exec -it single-node-wazuh.manager-1 chmod 660 /var/ossec/etc/ossec.conf
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

```

---

### 🚀 KỊCH BẢN SHOWCASE (BIỂU DIỄN) KHI BÁO CÁO ĐỒ ÁN

Khi bạn thêm tính năng này vào slide báo cáo, bạn sẽ có một luồng demo cực kỳ mượt mà và thuyết phục:

1. **Hành vi 1:** Máy Kali chạy lệnh `curl` tấn công LFI lần đầu tiên $\rightarrow$ Đọc được nội dung file `win.ini` thành công $\rightarrow$ Hệ thống Wazuh ghi nhận log, bóc tách bằng Decoder và nổ Alert Level 10 trên Dashboard.
2. **Hành vi tự động:** Ngay lập tức, Active Response kích hoạt, đẩy lệnh xuống Windows Firewall chặn đứng IP máy Kali.
3. **Hành vi 2 (Minh chứng chặn thành công):** Bạn quay lại máy Kali, gõ lại lệnh `curl` tấn công lần thứ hai $\rightarrow$ Lúc này lệnh `curl` sẽ bị treo cứng và báo **`Connection timed out`** giống hệt hiện tượng lúc nãy bạn gặp!

Đưa giải pháp phòng thủ chủ động này vào đoạn kết của Phase 3 là bài Lab của bạn đạt chuẩn chất lượng của một hệ thống SOC doanh nghiệp thực tế luôn. Bạn bổ sung thêm phần này vào đồ án nhé Toàn!
---

Toàn lưu lại quy trình chuẩn chỉnh có sẵn bước cài XAMPP này vào tài liệu nhé! Chúc bạn chạy bài Lab kịch bản 2 thành công mỹ mãn!