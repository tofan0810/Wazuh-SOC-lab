# TRIỂN KHAI CẤU HÌNH WAZUH AGENT TRÊN ENDPOINT (PHASE 2)

* **Dự án:** Nghiên cứu Kỹ thuật Phát hiện và Hệ thống Wazuh SIEM
* **Vị trí giả lập:** SOC Engineer / Detection Engineer
* **Môi trường thực hiện:** Windows 10 Pro (Máy ảo Victim chạy trên VMware)
* **Mục tiêu Phase 2:** Thực hiện đóng gói, cài đặt và kích hoạt hệ thống thu thập log (Wazuh Agent) trên máy trạm mục tiêu; thiết lập cơ chế xác thực an toàn (Authentication Key) để thiết lập kênh giao tiếp mã hóa thời gian thực về máy chủ trung tâm.

---

## I. QUY TRÌNH CÀI ĐẶT VÀ KHỞI TẠO ĐĂNG KÝ XÁC THỰC (AGENT ENROLLMENT)

Bản chất của Wazuh Agent trên Windows hoạt động như một dịch vụ hệ thống chạy ngầm (`WazuhSvc`). Để đảm bảo an toàn thông tin, Agent không thể kết nối tự do mà bắt buộc phải thực hiện thủ tục đăng ký để nhận "Thẻ thông hành" mã hóa từ Wazuh Manager.

### 1. Triển khai cài đặt gói phần mềm

* **Phiên bản đồng bộ:** `wazuh-agent-4.14.5-1.msi` (Đảm bảo khớp phiên bản với cụm trung tâm để tránh xung đột thư viện điều hướng log).
* **Yêu cầu hệ thống:** Thực thi dưới quyền quản trị tối cao (`Administrator`) để có quyền can thiệp vào phân hệ quản lý dịch vụ Windows Services.

### 2. Chuỗi lệnh cấu hình và ép nạp khóa xác thực (CLI Hardening)

Khi cài đặt bằng giao diện hoặc dòng lệnh cơ bản, hệ thống sẽ báo lỗi `Agent: Auth key not imported` và duy trì trạng thái `Not Running`. Tiến hành xử lý dứt điểm bằng cách mở **Command Prompt (CMD)** với quyền **Run as Administrator** và thực thi chuỗi lệnh sau:

```cmd
:: 1. Di chuyển vào thư mục phân phối gốc của Agent
cd "C:\Program Files (x86)\ossec-agent"

:: 2. Khai báo IP máy chủ Manager để kích hoạt tiến trình xin cấp khóa tự động
agent-auth.exe -m 192.168.71.128

:: 3. Tái khởi động dịch vụ hệ thống để áp dụng cấu hình mới
NET STOP WazuhSvc
NET START WazuhSvc
```

### 3. Kiểm chứng trạng thái hoạt động cục bộ trên Endpoint

Màn hình Command Prompt xuất hiện thông báo `Valid key received. Merging key and restarting...` và dịch vụ báo `started successfully`. Khi gọi giao diện quản trị nội bộ bằng tệp `win32ui.exe` (hoặc `wazuh-agentui.exe`), hệ thống xác nhận:

* **Manager IP:** Ghi nhận chính xác địa chỉ `192.168.71.128`.
* **Authentication Key:** Tự động điền chuỗi khóa băm bảo mật được cấp phát từ máy chủ.
* **Status:** Chuyển sang trạng thái **`Running`**.

![CMD thực thi lệnh xin cấp khóa thành công và giao diện đồ họa Wazuh Agent đạt trạng thái Status: Running](images/phase2/Install-wazuh-agent.png)

---

## II. KIỂM TRA ĐỘ ỔN ĐỊNH VÀ THÔNG LUỒNG DỮ LIỆU TRÊN SOC DASHBOARD

Sau khi Agent trên máy Victim kích hoạt trạng thái `Running`, luồng dữ liệu an ninh mạng ngay lập tức được đóng gói, mã hóa và đẩy về cổng dịch vụ trung tâm của Wazuh Manager.

### 1. Xác thực kết nối tổng quan (Agents Summary)

Truy cập giao diện Web Dashboard trung tâm tại địa chỉ `https://192.168.71.128`, hệ thống hiển thị biểu đồ trạng thái của toàn bộ hạ tầng giám sát:

* **Mục Active:** Chỉ số nhảy từ `0` lên **`1`** (Xác nhận có 1 Agent kết nối trực tiếp thành công).
* **Mục Disconnected:** Hiển thị `0` (Không có thiết bị kẹt kết nối hoặc mất tín hiệu).

### 2. Thu nhận tín hiệu Log hệ thống ban đầu

Mặc dù chưa triển khai các kịch bản tấn công thực chiến, phân hệ **Last 24 Hours Alerts** đã bắt đầu ghi nhận các sự kiện an ninh tiêu chuẩn được đẩy về từ máy trạm Windows 10 (bao gồm log kiểm toán hệ thống, sự thay đổi trạng thái tiến trình cục bộ) thuộc các phân lớp cảnh báo trung bình và thấp (`Medium severity` và `Low severity`). Điều này minh chứng kênh truyền thông SOC đã thông suốt 100%.

![Giao diện chính của Wazuh Dashboard với trạng thái Active (1) và biểu đồ cảnh báo đang thu nhận tín hiệu real-time](images/phase2/check-active.png)

---

## III. KẾT LUẬN & ĐỊNH HƯỚNG HOÀN THIỆN PHASE 2

Giai đoạn thiết lập kênh thu nhận log từ Endpoint (Wazuh Agent) về trung tâm điều hành SOC đã hoàn thành đạt mục tiêu đề ra, đảm bảo tính toàn vẹn và bảo mật dữ liệu qua kênh TLS/SSL.

**Kế hoạch thực hiện tiếp theo (Cấu hình nâng cao thu thập Log):**

1. Triển khai cài đặt công cụ kiểm toán chuyên sâu **Microsoft Sysmon** (System Monitor) trên máy Windows 10 Victim để bắt các hành vi can thiệp sâu vào bộ nhớ, tiến trình ngầm (Powershell, CMD) và kết nối mạng mờ ám.
2. Chỉnh sửa tệp cấu hình cấu trúc `ossec.conf` trên máy Victim để định hướng đẩy toàn bộ kênh Log của Sysmon (`Microsoft-Windows-Sysmon/Operational`) về máy chủ Wazuh Manager.
3. Nghiên cứu viết các bộ luật phát hiện tự chế (Custom Rules/Decoders) phục vụ cho Phase 3 (Mô phỏng tấn công Local File Inclusion - LFI hoặc Brute Force).