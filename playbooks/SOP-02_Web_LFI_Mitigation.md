# 📋 QUY TRÌNH ỨNG PHÓ SỰ CỐ: KHAI THÁC LỖ HỔNG WEB LFI / DIRECTORY TRAVERSAL (SOP-02)
> **Mã quy trình:** SOP-SOC-IR-002  
> **Kỹ thuật MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)  
> **Cảnh báo liên quan:** Wazuh Rule ID `100002` (WARNING: Local File Inclusion / Directory Traversal Attempt Detected - Level 10)  
> **Đối tượng áp dụng:** SOC Analyst L1/L2, Web Security Engineer, System/DevOps Admin  

---

## 🎯 1. TỔNG QUAN & MỤC TIÊU
Quy trình này cung cấp các bước ứng phó chuẩn khi hệ thống Wazuh SIEM phát hiện kẻ tấn công đang gửi các vector khai thác lỗ hổng **Local File Inclusion (LFI)** hoặc **Directory Traversal** (`../`, `..%2f`, `..%252f`) nhắm vào máy chủ Web Apache (XAMPP) trên máy chủ Windows để đọc trộm các file nhạy cảm của hệ điều hành (`win.ini`, cấu hình hệ thống) hoặc cố gắng nâng cấp lên thực thi mã từ xa (**RCE - Remote Code Execution**).

---

## 🔍 2. GIAI ĐOẠN 1: TIẾP NHẬN & PHÂN LOẠI BAN ĐẦU (IDENTIFICATION & TRIAGE - SOC L1)

### Bước 2.1: Bóc tách thông tin cảnh báo từ Wazuh
Khi nhận Alert **Rule 100002**, trích xuất các trường dữ liệu quan trọng:
* `data.srcip`: IP của kẻ tấn công (ví dụ: `192.168.71.130`).
* `data.url`: Đường dẫn URL đầy đủ chứa chuỗi payload độc hại (ví dụ: `/index.php?page=../../../../Windows/win.ini` hoặc `..%252f`).
* `data.id`: Mã phản hồi HTTP (HTTP Status Code) do Apache trả về (ví dụ: `200`, `403`, `404`).

### Bước 2.2: Đánh giá tác động (Impact Analysis)
Phân tích giá trị HTTP Status Code để xác định mức độ thành công của cuộc tấn công:

* **Trường hợp 1 — HTTP Code `200 OK` (Cực kỳ nguy hiểm - Severity P1/P2):**
  * Web Server đã tiếp nhận tham số, hàm `include()` đã thực thi và **đọc thành công** tệp tin nhạy cảm đẩy ra trình duyệt của kẻ tấn công.
  * *Hành động:* Nâng mức nghiêm trọng lên **P1 - Critical**, chuyển giao ngay cho L2 để tiến hành rà soát rò rỉ dữ liệu và nguy cơ Web Shell.
* **Trường hợp 2 — HTTP Code `404 Not Found` hoặc `403 Forbidden` (Severity P3 - Medium):**
  * Kẻ tấn công đang gửi payload thăm dò (Fuzzing) hoặc cố gắng đọc một file không tồn tại / bị hệ điều hành chặn quyền đọc.
  * Kẻ tấn công chưa lấy được dữ liệu nhưng đang tích cực trinh sát hệ thống.
* **Trường hợp 3 — Kỹ thuật vượt rào (Bypass Technique):**
  * Cần kiểm tra xem URL có chứa mã hóa đơn (`%2f`) hoặc mã hóa kép (`%252f`) không. Nếu có, đây là dấu hiệu rõ ràng của một cuộc tấn công có chủ đích (Targeted Attack) nhằm qua mặt WAF/IDS.

---

## 🛡️ 3. GIAI ĐOẠN 2: CÔ LẬP SỰ CỐ (CONTAINMENT - SOC L2)

### Bước 3.1: Kiểm tra trạng thái Active Response của Wazuh
Xác minh xem Wazuh Agent đã chặn IP của attacker trên Windows Defender Firewall chưa:
```powershell
# Kiểm tra log Active Response:
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 10 | Select-String "100002"

# Kiểm tra rule tường lửa:
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
```

### Bước 3.2: Can thiệp khẩn cấp nếu Active Response chưa chặn được
1. **Chặn IP nguồn trên tường lửa Windows:**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_BLOCK_LFI_ATTACKER_192.168.71.130" -Direction Inbound -Action Block -RemoteAddress 192.168.71.130
   ```
2. **Nếu nghi ngờ hệ thống đang bị khai thác ồ ạt:**
   Tạm dừng ứng dụng Web để khoanh vùng và bảo vệ dữ liệu nhạy cảm:
   ```cmd
   :: Dừng ngay dịch vụ Apache từ command line:
   C:\xampp\apache\bin\httpd.exe -k stop
   ```

---

## 🔬 4. GIAI ĐOẠN 3: ĐIỀU TRA SÂU & RÀ SOÁT WEB SHELL (INVESTIGATION & ERADICATION)

Một cuộc tấn công LFI thường chỉ là bước đệm. Kẻ tấn công sẽ cố gắng biến LFI thành **RCE (Remote Code Execution)** thông qua kỹ thuật **Log Poisoning** (đầu độc file log Apache) hoặc tải lên tệp tin Web Shell.

### Bước 4.1: Sử dụng Telemetry của Sysmon để phát hiện RCE
Đây là nơi Sysmon phát huy sức mạnh vượt trội so với log web thông thường:

1. **Kiểm tra Tiến trình con bất thường (Sysmon Event ID 1 - Process Creation):**
   Tiến trình Web Server (`httpd.exe` hoặc `php-cgi.exe`) **KHÔNG BAO GIỜ** được phép sinh ra các tiến trình dòng lệnh hệ thống.
   ```powershell
   # Tìm kiếm sự kiện tiến trình Apache gọi CMD hoặc PowerShell:
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-4)} | Where-Object {
       $_.Properties[21].Value -like "*httpd.exe*" -and ($_.Properties[4].Value -like "*cmd.exe*" -or $_.Properties[4].Value -like "*powershell.exe*" -or $_.Properties[4].Value -like "*whoami.exe*")
   }
   ```
   👉 *Nếu tìm thấy: Kẻ tấn công đã thực thi mã từ xa thành công!*

2. **Kiểm tra File mới được tạo trong thư mục Web (Sysmon Event ID 11 - FileCreate):**
   Kiểm tra xem Apache có vừa tạo ra file script nào (`.php`, `.phtml`, `.jsp`, `.exe`) trong thư mục web không:
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=(Get-Date).AddHours(-4)} | Where-Object {
       $_.Properties[4].Value -like "C:\xampp\htdocs\*" -and $_.Properties[4].Value -match "\.(php|phtml|exe|bat|ps1)$"
   }
   ```

### Bước 4.2: Rà soát Log Poisoning trong Apache Logs
Kiểm tra xem kẻ tấn công có chèn mã độc PHP vào User-Agent hoặc URL để lưu vào file log hay không:
```powershell
Select-String -Path "C:\xampp\apache\logs\access.log" -Pattern "(<\?php|eval\(|system\(|passthru\()"
```

### Bước 4.3: Xóa bỏ tệp tin độc hại
* Nếu phát hiện file lạ trong `C:\xampp\htdocs\`: Cách ly file đó vào thư mục kiểm dịch (`C:\Quarantine\`) để phân tích mã độc trước khi xóa bỏ.
* Khởi động lại Apache sau khi đã làm sạch.

---

## 🛠️ 5. GIAI ĐOẠN 4: VÁ LỖ HỔNG MÃ NGUỒN & KHÔI PHỤC (REMEDIATION & RECOVERY)

### Bước 5.1: Vá mã nguồn PHP dính lỗ hổng LFI (Root Cause Fix)

#### ❌ Mã nguồn dính lỗ hổng ban đầu (`C:\xampp\htdocs\index.php`):
```php
<?php
    // NGUY HIỂM: Nạp trực tiếp tham số mà không kiểm tra đầu vào
    if (isset($_GET['page'])) {
        $file = $_GET['page'];
        include($file);
    }
?>
```

#### ✅ Mã nguồn đã được vá an toàn (Whitelisting & Path Sanitization):
```php
<?php
    // DANH SÁCH TRẮNG (WHITELIST): Chỉ cho phép các trang hợp lệ
    $allowed_pages = [
        'home'    => 'pages/home.php',
        'about'   => 'pages/about.php',
        'contact' => 'pages/contact.php'
    ];

    if (isset($_GET['page'])) {
        $page = $_GET['page'];
        
        // Kiểm tra nghiêm ngặt: Chỉ nạp file nếu nằm trong danh sách trắng
        if (array_key_exists($page, $allowed_pages) && file_exists($allowed_pages[$page])) {
            include($allowed_pages[$page]);
        } else {
            http_response_code(404);
            echo "<h1>404 - Trang yêu cầu không tồn tại!</h1>";
        }
    } else {
        include('pages/home.php');
    }
?>
```

### Bước 5.2: Khởi động lại và kiểm tra dịch vụ
1. Lưu file mã nguồn đã vá.
2. Khởi động lại dịch vụ Apache:
   ```cmd
   C:\xampp\apache\bin\httpd.exe -k restart
   ```
3. Chạy lại kịch bản kiểm thử tự động của SOC để xác minh lỗ hổng đã được bít hoàn toàn:
   ```powershell
   python tests/e2e/scenario_lfi_web.py --execute
   ```

---

## 🛡️ 6. GIAI ĐOẠN 5: RÚT KINH NGHIỆM & GIA CỐ HỆ THỐNG (HARDENING)

### Biện pháp 1: Khóa chặt phạm vi truy cập tệp bằng `open_basedir` trong `php.ini`
Cấu hình chỉ thị `open_basedir` để ngăn chặn tuyệt đối PHP đọc bất kỳ tệp tin nào nằm ngoài thư mục web, kể cả khi mã nguồn vẫn còn lỗ hổng traversal.

* Mở file `C:\xampp\php\php.ini`:
  ```ini
  ; Giới hạn PHP chỉ được phép truy cập thư mục htdocs và thư mục temp
  open_basedir = "C:\xampp\htdocs;C:\xampp\tmp"
  
  ; Tắt khả năng nạp file từ URL từ xa (chống RFI - Remote File Inclusion)
  allow_url_fopen = Off
  allow_url_include = Off
  
  ; Ẩn phiên bản PHP và ẩn chi tiết lỗi hệ thống ra màn hình
  expose_php = Off
  display_errors = Off
  log_errors = On
  ```

### Biện pháp 2: Chạy Apache dưới tài khoản người dùng có quyền tối thiểu (Least Privilege)
Không bao giờ chạy Apache dưới tài khoản Administrator. Tạo một tài khoản dịch vụ riêng (`svc_apache`) chỉ có quyền đọc thư mục `htdocs` và không có quyền đọc thư mục hệ thống `C:\Windows`.

### Biện pháp 3: Triển khai Web Application Firewall (WAF)
Tích hợp module **ModSecurity** hoặc Reverse Proxy (Nginx/Cloudflare) trước máy chủ Web để tự động nhận diện và chặn đứng các chuỗi `../` và `%252f` ngay tại tầng mạng trước khi gói tin chạm tới tầng ứng dụng Apache.
