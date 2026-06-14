# PHỤ LỤC A. CÁC THAO TÁC QUẢN TRỊ WAZUH TRÊN DOCKER

## A.1. Khởi động và dừng hệ thống Wazuh

Trong quá trình triển khai, Wazuh được cài đặt theo mô hình Single Node sử dụng Docker Compose. Các lệnh quản trị cơ bản được sử dụng thường xuyên như sau.

### Dừng toàn bộ hệ thống

Trước khi tắt máy ảo hoặc thực hiện bảo trì hệ thống, nên dừng toàn bộ dịch vụ Wazuh:

```bash
sudo docker compose stop
```

Lệnh này dừng các container Dashboard, Manager và Indexer nhưng vẫn giữ nguyên dữ liệu.

---

### Khởi động lại hệ thống

Khởi động toàn bộ cụm dịch vụ Wazuh ở chế độ chạy nền:

```bash
sudo docker compose up -d
```

Trong đó:

* `up`: khởi tạo và chạy các container.
* `-d`: chạy ở chế độ nền (Detached Mode).

---

### Khởi động lại riêng Wazuh Manager

Sau khi chỉnh sửa Rule hoặc Decoder, cần khởi động lại Manager để nạp cấu hình mới:

```bash
sudo docker compose restart wazuh.manager
```

---

## A.2. Kiểm tra trạng thái các container

Xem danh sách container đang hoạt động:

```bash
sudo docker ps
```

Kiểm tra tiến trình con
```
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
```

Xem toàn bộ container bao gồm cả container đã dừng:

```bash
sudo docker ps -a
```

Kết quả mong muốn:

```text
single-node-wazuh.dashboard-1
single-node-wazuh.manager-1
single-node-wazuh.indexer-1
```

đều ở trạng thái:

```text
Up
```

---

## A.3. Truy cập Wazuh Manager Container

Để thực hiện các thao tác quản trị nâng cao, cần truy cập vào container Manager:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

Sau khi thực hiện, dấu nhắc lệnh sẽ chuyển thành:

```bash
bash-5.2#
```

Từ đây có thể chỉnh sửa Rule, Decoder hoặc kiểm tra trạng thái dịch vụ Wazuh.

---

## A.4. Sao lưu và chỉnh sửa Custom Rule

Do container Manager không cài sẵn trình soạn thảo văn bản như nano hoặc vim, việc chỉnh sửa Rule được thực hiện trên máy chủ Ubuntu rồi sao chép trở lại container.

### Bước 1. Sao chép file Rule từ container ra máy chủ

```bash
sudo docker cp \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml \
~/local_rules.xml
```

Kiểm tra file đã được sao chép:

```bash
ls -l ~/local_rules.xml
```

---

### Bước 2. Chỉnh sửa file Rule trên Ubuntu

```bash
nano ~/local_rules.xml
```

hoặc:

```bash
gedit ~/local_rules.xml
```

Thêm hoặc chỉnh sửa các Custom Rule theo yêu cầu.

---

### Bước 3. Sao chép file đã chỉnh sửa trở lại container

```bash
sudo docker cp \
~/local_rules.xml \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
```

---

### Bước 4. Cấp lại quyền cho file Rule

Truy cập container:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

Thiết lập lại chủ sở hữu:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
```

Cấp quyền truy cập:

```bash
chmod 660 /var/ossec/etc/rules/local_rules.xml
```

Kiểm tra:

```bash
ls -l /var/ossec/etc/rules/local_rules.xml
```

Kết quả mong muốn:

```text
-rw-rw---- 1 wazuh wazuh
```

---

## A.5. Kiểm tra tính hợp lệ của Rule

Sau khi chỉnh sửa Rule, cần kiểm tra cú pháp trước khi khởi động lại Manager:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Nếu cấu hình hợp lệ, lệnh sẽ kết thúc mà không xuất hiện thông báo:

```text
ERROR
CRITICAL
```

Nếu xuất hiện lỗi, cần chỉnh sửa lại Rule trước khi tiếp tục.

---

## A.6. Kiểm tra log Wazuh Manager

Xem log thời gian thực:

```bash
sudo docker logs -f single-node-wazuh.manager-1
```

Xem 50 dòng log gần nhất:

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 50
```

Các log này giúp xác định lỗi liên quan đến:

* Rules.
* Decoders.
* Active Response.
* Filebeat.
* Kết nối Indexer.

---

## A.7. Kiểm tra log Dashboard

```bash
sudo docker logs single-node-wazuh.dashboard-1 --tail 50
```

Dùng để phân tích các lỗi giao diện Dashboard hoặc lỗi API.

---

## A.8. Kiểm tra log Indexer

```bash
sudo docker logs single-node-wazuh.indexer-1 --tail 50
```

Dùng để phân tích lỗi lưu trữ dữ liệu, lỗi OpenSearch hoặc lỗi kết nối giữa Manager và Indexer.

---

## A.9. Kiểm tra nội dung Rule hiện tại

Hiển thị nội dung file local_rules.xml:

```bash
cat /var/ossec/etc/rules/local_rules.xml
```

Liệt kê toàn bộ thư mục Rules:

```bash
ls -l /var/ossec/etc/rules/
```

---

## A.10. Một số thao tác xử lý sự cố thường gặp

### Dashboard báo lỗi 500

Kiểm tra:

```bash
sudo docker ps
```

Đảm bảo:

```text
single-node-wazuh.dashboard-1
single-node-wazuh.manager-1
single-node-wazuh.indexer-1
```

đều đang ở trạng thái hoạt động.

---

### Khởi động lại toàn bộ hệ thống

```bash
sudo docker compose restart
```

---

### Kiểm tra kết nối giữa Manager và Indexer

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 100
```

Nếu xuất hiện:

```text
Connection established
```

thì Manager đã kết nối thành công tới Indexer.

---

## A.11. Các đường dẫn quan trọng trong Wazuh

| Thành phần      | Đường dẫn                              |
| --------------- | -------------------------------------- |
| Cấu hình chính  | `/var/ossec/etc/ossec.conf`            |
| Custom Rules    | `/var/ossec/etc/rules/local_rules.xml` |
| Custom Decoders | `/var/ossec/etc/decoders/`             |
| Alerts JSON     | `/var/ossec/logs/alerts/alerts.json`   |
| Active Response | `/var/ossec/active-response/bin/`      |
| Agent Keys      | `/var/ossec/etc/client.keys`           |

Các đường dẫn trên được sử dụng thường xuyên trong quá trình xây dựng Rule, Decoder và Active Response.
