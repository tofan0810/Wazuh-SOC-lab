# Cơ sở lý thuyết về SMB và RDP

## 1. Giao thức SMB (Server Message Block)

SMB là giao thức mạng được Microsoft phát triển nhằm hỗ trợ việc chia sẻ tài nguyên trong môi trường Windows như tập tin, thư mục, máy in và các dịch vụ mạng khác.

SMB hoạt động chủ yếu trên cổng TCP 445 và cho phép người dùng truy cập tài nguyên từ xa thông qua cơ chế xác thực tài khoản Windows.

Trong môi trường doanh nghiệp, SMB thường được sử dụng để:

* Chia sẻ thư mục dùng chung.
* Truy cập máy chủ tập tin (File Server).
* Quản lý tài nguyên trong mạng nội bộ.

Do sử dụng cơ chế xác thực tài khoản Windows, SMB thường là mục tiêu của các cuộc tấn công Brute Force nhằm dò đoán tên đăng nhập và mật khẩu.

---

## 2. Giao thức RDP (Remote Desktop Protocol)

RDP là giao thức điều khiển máy tính từ xa do Microsoft phát triển, cho phép người dùng truy cập và thao tác trực tiếp trên giao diện Desktop của hệ điều hành Windows thông qua mạng.

RDP hoạt động mặc định trên cổng TCP 3389.

Các chức năng chính của RDP:

* Điều khiển máy tính từ xa.
* Hỗ trợ quản trị hệ thống.
* Hỗ trợ làm việc từ xa.

Do cung cấp quyền truy cập trực tiếp vào hệ thống, RDP là một trong những dịch vụ thường xuyên bị tấn công Brute Force trong môi trường doanh nghiệp.

Theo MITRE ATT&CK, hành vi dò quét và thử nhiều mật khẩu liên tục trên RDP thuộc kỹ thuật T1110 – Brute Force.

---

## 3. So sánh SMB và RDP

| Tiêu chí                            | SMB                   | RDP                       |
| ----------------------------------- | --------------------- | ------------------------- |
| Mục đích                            | Chia sẻ tài nguyên    | Điều khiển máy tính từ xa |
| Cổng mặc định                       | TCP 445               | TCP 3389                  |
| Quyền truy cập                      | File, Folder, Printer | Toàn bộ Desktop           |
| Mức độ nguy hiểm khi bị chiếm quyền | Trung bình            | Cao                       |
| Thường bị Brute Force               | Có                    | Rất phổ biến              |
| Mức độ xuất hiện trong doanh nghiệp | Cao                   | Rất cao                   |

Trong phạm vi đồ án này, giao thức RDP được lựa chọn để mô phỏng tấn công Brute Force do đây là một trong những hình thức tấn công phổ biến nhất đối với hệ thống Windows trong môi trường thực tế.
