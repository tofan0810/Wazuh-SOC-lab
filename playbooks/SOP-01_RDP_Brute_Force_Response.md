# 📋 QUY TRÌNH ỨNG PHÓ SỰ CỐ: TẤN CÔNG DÒ QUÉT MẬT KHẨU RDP (SOP-01)
> **Mã quy trình:** SOP-SOC-IR-001  
> **Kỹ thuật MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) / [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)  
> **Cảnh báo liên quan:** Wazuh Rule ID `100001` (Windows Brute Force Attack Detected - Level 12)  
> **Đối tượng áp dụng:** SOC Analyst L1/L2, Incident Response Team, Windows System Admin  

---

## 🎯 1. TỔNG QUAN & MỤC TIÊU
Quy trình này hướng dẫn chi tiết các bước xác minh, phân loại mức độ nghiêm trọng, cô lập tức thời và khắc phục hậu quả khi hệ thống SIEM Wazuh phát hiện hành vi dò quét mật khẩu dồn dập nhắm vào dịch vụ Remote Desktop (RDP - Port 3389) trên các máy chủ/máy trạm Windows Endpoint.

---

## 🔍 2. GIAI ĐOẠN 1: TIẾP NHẬN & PHÂN LOẠI BAN ĐẦU (IDENTIFICATION & TRIAGE - SOC L1)

Khi nhận được Alert **Rule 100001** từ Wazuh Dashboard hoặc kênh Telegram, Analyst L1 tiến hành điều tra theo 3 bước sau:

### Bước 2.1: Thu thập thông tin Alert từ Wazuh
Trích xuất các trường dữ liệu cốt lõi trong log JSON:
* `data.win.eventdata.targetUserName`: Tên tài khoản bị tấn công (ví dụ: `testw`, `administrator`, `admin`).
* `data.win.eventdata.ipAddress`: Địa chỉ IP nguồn phát động tấn công (ví dụ: `192.168.71.130`).
* `data.win.eventdata.logonType`: Loại hình đăng nhập (`10` = RemoteInteractive / RDP).
* `data.win.eventdata.status` / `subStatus`: Mã lỗi xác thực của Windows:
  * `0xC000006A`: Mật khẩu sai (User name is correct, but password is bad).
  * `0xC0000064`: Tài khoản không tồn tại trên hệ thống (User name does not exist).
  * `0xC0000234`: Tài khoản đã bị khóa do vượt ngưỡng (User account currently locked out).

### Bước 2.2: Phân biệt Tấn công thực tế vs Báo động giả (False Positive)

| Tiêu chí phân loại | Người dùng hợp lệ quên mật khẩu | Tấn công tự động (Hydra, xfreerdp, Medusa) |
| :--- | :--- | :--- |
| **Tốc độ (Velocity)** | 2 – 5 lần thất bại trong 1 – 2 phút. | **> 10 lần chỉ trong vài giây** (tần suất dồn dập). |
| **Đa dạng Username** | Chỉ gõ sai đúng 1 tài khoản của cá nhân. | Dò quét hàng loạt tài khoản mặc định (`admin`, `root`, `user`, `administrator`). |
| **Vị trí IP nguồn** | Đến từ dải mạng nội bộ quen thuộc của phòng ban. | Đến từ dải IP lạ, máy trạm bên ngoài, hoặc máy ảo kiểm thử (`192.168.71.130`). |
| **Mã lỗi SubStatus** | Đa số là `0xC000006A` (sai mật khẩu). | Xuất hiện liên tiếp nhiều lỗi `0xC0000064` (thử bừa username từ wordlist). |

### Bước 2.3: KIỂM TRA QUAN TRỌNG NHẤT — Kẻ tấn công đã vào được hệ thống chưa?
Một trong những lỗi nghiêm trọng nhất của SOC Analyst là chỉ báo "đã chặn Brute Force" mà không kiểm tra xem hacker đã dò trúng pass hay chưa.

* **Truy vấn trên Wazuh Dashboard (Discover) hoặc Windows Event Viewer:**
  Tìm kiếm sự kiện **Event ID 4624 (Logon Thành Công)** phát sinh ngay sau chuỗi Event 4625 từ cùng một IP:
  ```powershell
  # Chạy kiểm tra nhanh trên Windows qua WinRM/PowerShell:
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-30)} | Where-Object { $_.Properties[18].Value -eq '192.168.71.130' -and $_.Properties[8].Value -eq 10 }
  ```
* **Đánh giá rủi ro:**
  * **Nếu CÓ Event 4624 Type 10:** 🚨 **BÁO ĐỘNG ĐỎ (Severity P1 - Critical)**. Kẻ tấn công đã chiếm được quyền điều khiển máy! Chuyển ngay sang quy trình xử lý mã độc và điều tra xâm nhập sâu.
  * **Nếu KHÔNG CÓ Event 4624:** ⚠️ **Severity P3 - Medium** (nếu Active Response đã chặn thành công) hoặc **Severity P2 - High** (nếu chưa chặn được IP).

---

## 🛡️ 3. GIAI ĐOẠN 2: CÔ LẬP SỰ CỐ (CONTAINMENT - SOC L2)

### Bước 3.1: Kiểm tra trạng thái tự động của Active Response
Kiểm tra xem Wazuh Agent đã áp dụng quy tắc chặn qua `netsh.exe` hay chưa:
```powershell
# Kiểm tra log phản ứng của Agent:
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 5

# Kiểm tra rule tường lửa Windows đang có hiệu lực:
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*WAZUH*"} | Select-Object DisplayName, Action, Enabled
```

### Bước 3.2: Biện pháp can thiệp thủ công (Fallback khi Active Response bị lỗi)
Nếu vì lý do gì Active Response không kích hoạt hoặc rule tường lửa bị xung đột:

1. **Khóa cứng IP tấn công ngay lập tức bằng PowerShell:**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_EMERGENCY_BLOCK_192.168.71.130" -Direction Inbound -Action Block -RemoteAddress 192.168.71.130
   ```
2. **Nếu kẻ tấn công đang có phiên RDP hoạt động (Active Session):**
   ```cmd
   :: Liệt kê các session RDP đang kết nối:
   qwinsta
   
   :: Ngắt kết nối và đóng ngay phiên của kẻ tấn công (ví dụ session ID = 2):
   rwinsta 2
   ```
3. **Cô lập máy tính khỏi mạng cục bộ (Network Isolation):**
   Nếu nghi ngờ máy tính đã bị chiếm quyền hoàn toàn, ngắt kết nối mạng ngay lập tức để ngăn chặn di chuyển ngang (Lateral Movement):
   ```powershell
   # Tắt adapter mạng trên máy Windows:
   Disable-NetAdapter -Name "Ethernet0" -Confirm:$false
   ```

---

## 🧹 4. GIAI ĐOẠN 3: DIỆT TRỪ NGUY CƠ (ERADICATION)

1. **Khóa và vô hiệu hóa tài khoản bị nhắm tới:**
   Nếu tài khoản bị dò mật khẩu (ví dụ `testw`) có nguy cơ bị lộ mật khẩu yếu:
   ```powershell
   # Vô hiệu hóa tài khoản tạm thời:
   Disable-LocalUser -Name "testw"
   
   # Thu hồi toàn bộ token đăng nhập và reset mật khẩu sang chuỗi ngẫu nhiên mạnh:
   $newPass = [System.Web.Security.Membership]::GeneratePassword(16, 4)
   Set-LocalUser -Name "testw" -Password ($newPass | ConvertTo-SecureString -AsPlainText -Force)
   ```
2. **Kiểm tra rà soát hành vi bất thường sau xâm nhập (nếu nghi ngờ breach):**
   * **Sysmon Event ID 1 (Process Create):** Kiểm tra xem trong khoảng thời gian tấn công có tiến trình lạ nào được sinh ra từ `rdpclip.exe` hoặc `userinit.exe` không.
   * **Kiểm tra tài khoản mới được tạo lén lút (Event ID 4720):**
     ```powershell
     Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=(Get-Date).AddHours(-2)}
     ```
   * **Kiểm tra các cổng mạng đang lắng nghe bất thường (Backdoor):**
     ```powershell
     netstat -ano | Select-String "LISTENING"
     ```

---

## 🔄 5. GIAI ĐOẠN 4: PHỤC HỒI & KIỂM TRA HỆ THỐNG (RECOVERY)

1. Mở khóa tài khoản người dùng sau khi đã được cấp phát mật khẩu mới phức tạp (tối thiểu 12 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt).
2. Kích hoạt lại card mạng (nếu trước đó đã cách ly):
   ```powershell
   Enable-NetAdapter -Name "Ethernet0" -Confirm:$false
   ```
3. Kiểm tra tính toàn vẹn của dịch vụ: Chạy script kiểm thử sức khỏe hạ tầng:
   ```powershell
   python tests/e2e/lab_health.py
   ```
4. Thiết lập chế độ giám sát tăng cường (Enhanced Monitoring) đối với IP và User đó trong vòng **48 giờ tiếp theo**.

---

## 🛡️ 6. GIAI ĐOẠN 5: RÚT KINH NGHIỆM & GIA CỐ HỆ THỐNG (LESSONS LEARNED & HARDENING)

Để triệt tiêu hoàn toàn nguy cơ tấn công dò quét mật khẩu RDP trong tương lai, áp dụng các biện pháp gia cố kỹ thuật sau:

### Biện pháp 1: Bắt buộc kích hoạt Network Level Authentication (NLA)
NLA yêu cầu người dùng phải xác thực danh tính với hệ điều hành trước khi phiên làm việc đồ họa RDP được khởi tạo, ngăn chặn các công cụ quét tự động gửi dữ liệu trực tiếp vào hệ điều hành.
```powershell
# Kích hoạt NLA qua PowerShell:
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(1)
```

### Biện pháp 2: Cấu hình Chính sách Khóa tài khoản (Account Lockout Policy)
Thiết lập tự động khóa tài khoản sau 5 lần đăng nhập thất bại trong vòng 15 phút:
```cmd
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
```

### Biện pháp 3: Đổi cổng kết nối RDP mặc định (Security through Obscurity)
Chuyển cổng lắng nghe RDP từ `3389` sang một cổng ngẫu nhiên (ví dụ `33890`) để tránh các công cụ quét tự động đại trà:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value 33890
New-NetFirewallRule -DisplayName "RDP_Custom_Port_33890" -Direction Inbound -LocalPort 33890 -Protocol TCP -Action Allow
```

### Biện pháp 4: Giới hạn IP truy cập RDP (IP Whitelisting)
Chỉ cho phép kết nối RDP từ các máy quản trị hoặc dải IP VPN nội bộ được chỉ định, chặn toàn bộ kết nối trực tiếp từ Internet.
```powershell
Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -RemoteAddress "192.168.71.1/24"
```
