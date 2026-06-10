# CÁC KỊCH BẢN TẤN CÔNG & PHÁT HIỆN THỰC CHIẾN (PHASE 3)

## 🔹 KỊCH BẢN 1: T1110 - PHÁT HIỆN TẤN CÔNG BRUTE FORCE & TỰ ĐỘNG KHÓA IP (ACTIVE RESPONSE)

Kịch bản này chứng minh năng lực **Phản ứng chủ động (Active Response)** của hệ thống SIEM – không chỉ dừng lại ở việc phát hiện mà còn trực tiếp can thiệp vào tường lửa để cô lập kẻ tấn công ngay trong thời gian thực.

### 1. Mục tiêu

Mục tiêu của Phase 3 - Kịch bản 1 là mô phỏng một cuộc tấn công Brute Force từ máy Kali Linux vào máy Windows Victim và sử dụng Wazuh để phát hiện các lần xác thực thất bại thông qua Windows Security Event Log.

Kết quả mong muốn:

* Windows Agent gửi log về Wazuh Manager.
* Wazuh phát hiện các lần đăng nhập thất bại.
* Xây dựng Custom Rule phát hiện Brute Force.
* Mapping với MITRE ATT&CK T1110 (Brute Force).

---

### 2. Mô hình triển khai

Mô hình triển khai bao gồm ba thành phần chính:

```
                   ┌───────────────┐
                   │ Kali Linux    │
                   │ Attacker      │
                   └───────┬───────┘
                           │
                           │ RDP Brute Force
                           ▼
                   ┌───────────────┐
                   │ Windows 10    │
                   │ Wazuh Agent   │
                   └───────┬───────┘
                           │
                           │ Security Logs
                           ▼
                   ┌───────────────┐
                   │ Wazuh Manager │
                   │ Docker        │
                   └───────┬───────┘
                           │
                           │ Alerts
                           ▼
                   ┌───────────────┐
                   │ Dashboard     │
                   │ Threat Hunt   │
                   └───────────────┘
```
--- 

## 3. Kiểm tra dịch vụ RDP

Từ Kali Linux tiến hành quét cổng RDP của máy Windows.
```bash
nmap -Pn -p 3389 192.168.71.129
```

Kết quả:
```text
3389/tcp open ms-wbt-server
```

=> Điều này xác nhận dịch vụ Remote Desktop đang hoạt động và sẵn sàng tiếp nhận kết nối từ xa.
![Kết quả quét cổng 3389 bằng Nmap](images/phase3/kichban1/checkRDP.png)

---

## 4. Mô phỏng đăng nhập thất bại qua RDP

Sử dụng công cụ xfreerdp trên Kali Linux.
```bash
xfreerdp /u:testw /p:wrongpassword /v:192.168.71.129 /cert:ignore
```

Kết quả:
```text
ERRCONNECT_LOGON_FAILURE
```

=> Điều này chứng minh máy Windows đã tiếp nhận yêu cầu xác thực và từ chối đăng nhập do mật khẩu không chính xác.
![Đăng nhập RDP thất bại bằng xfreerdp](images/phase3/kichban1/simulationRDP.png)

---
## 5. Xây dựng Custom Rule phát hiện Brute Force

Bổ sung Rule trong file local_rules.xml, xem tại **link dẫn đến local_rules.xml trong custom-rules/**:

## 6. Mô phỏng tấn công Brute Force

Tiến hành gửi nhiều yêu cầu xác thực sai liên tiếp.
```bash
for i in {1..10}; do
    xfreerdp /u:testw \
             /p:wrongpassword \
             /v:192.168.71.129 \
             /cert:ignore
done
```

Lệnh trên tạo ra nhiều sự kiện đăng nhập thất bại trong thời gian ngắn trên hệ thống Windows.
![Mô phỏng Brute Force RDP](images/phase3/kichban1/simulationBruteForce.png)

---

## 7. Kiểm tra Event Log trên Windows

Sau khi thực hiện tấn công mô phỏng, kiểm tra Security Event Log.
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}
```

Kết quả xuất hiện nhiều sự kiện:
```text
Event ID: 4625
An account failed to log on
```

Event ID 4625 là sự kiện chuẩn của Windows dùng để ghi nhận các lần đăng nhập thất bại.
![Event ID 4625 trên Windows Security Log](images/phase3/kichban1/CheckWinEventLog.png)

---

## 8. Phân tích log trên Wazuh Dashboard

Truy cập Threat Hunting và ta thấy được rule.id là 100001 ta vừa tạo

```text
Windows Brute Force Attack Detected
Rule ID: 100001
Level : 12
```

![Wazuh ghi nhận các lần đăng nhập thất bại](images/phase3/kichban1/100001.png)

---

## 9. Kết quả đạt được

Hệ thống đã:

* Thu thập thành công Windows Security Event Logs.
* Ghi nhận Event ID 4625.
* Sinh cảnh báo Rule ID 60122.
* Kích hoạt Custom Rule 100001.
* Mapping thành công với MITRE ATT&CK T1110.
* Sẵn sàng triển khai Active Response ở giai đoạn tiếp theo.

## 10. Kết luận

Kịch bản đã chứng minh khả năng phát hiện tấn công Brute Force RDP trong môi trường Windows bằng Wazuh. Hệ thống không chỉ thu thập và phân tích Security Event Logs mà còn có khả năng mở rộng để tự động phản ứng thông qua cơ chế Active Response trong các giai đoạn tiếp theo.










































---
###1. Sơ đồ cơ chế hoạt động (Workflow)

###2. Kỹ thuật giả lập tấn công (Attack Simulation)

* **Công cụ thực thi:** Sử dụng `Hydra` trên máy Kali Linux (IP giả lập: `192.168.71.130`).
* **Mục tiêu:** Tấn công rà quét mật khẩu tài khoản `testw` qua dịch vụ SSH (nếu mục tiêu là Ubuntu) hoặc RDP (nếu mục tiêu là Windows). Trong bài Lab này, ta thực hiện hướng vào dịch vụ SSH của chính máy chủ hoặc một Endpoint Linux để minh họa rõ nhất script khóa IP.
* **Câu lệnh triển khai từ máy Kali Linux:**
```bash
hydra -l testw -P /usr/share/wordlists/rockyou.txt ssh://192.168.71.128 -t 4 -V

```

*(Lệnh này ép Hydra thử liên tục hàng trăm mật khẩu từ từ điển `rockyou.txt` vào mục tiêu với tốc độ cao, sinh ra hàng loạt sự kiện đăng nhập thất bại trong vài giây).*

###3. Thu thập Telemetry (Log Source)

* Hệ thống tự động thu thập thông qua Event log hệ điều hành:
* **Linux:** Toàn bộ các dòng log `Authentication failure` ghi nhận trong tệp thô `/var/log/auth.log`.
* **Windows (nếu dùng RDP):** Ghi nhận mã **Security Event ID 4625** (An account failed to log on).



###4. Kỹ thuật viết Luật phát hiện tùy biến (Custom Rules Engineering)

Mặc định, Wazuh đã có rule bắt hành vi đăng nhập sai, nhưng để kích hoạt chế độ **Active Response** tự động khóa IP khi có dấu hiệu Brute Force dồn dập, ta cần cấu hình một bộ luật lồng nhau (Composite Rule) trong tệp `/var/ossec/etc/rules/local_rules.xml` trên Wazuh Manager:

```xml
<group name="attack,bruteforce,">
  <rule id="100001" level="10">
    <if_matched_sid>5716</if_matched_sid> <same_source_ip />
    <frequency>8</frequency>
    <timeframe>10</timeframe>
    <description>CẢNH BÁO: Phát hiện hành vi Brute Force SSH dồn dập từ IP nguồn.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

###5. Cấu hình Phản ứng giảm thiểu tự động (Active Response Configuration)

Để Wazuh tự động thực thi script chặn IP, ta tiến hành khai báo cấu hình khối lệnh (`command`) và khối phản ứng (`active-response`) vào file cấu hình hệ thống máy chủ `/var/ossec/etc/ossec.conf` trên Wazuh Manager:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100001</rules_id>
  <timeout>600</timeout> </active-response>

```

*Sau khi lưu file, thực hiện restart lại cụm cụm trung tâm bằng lệnh: `sudo docker compose restart`.*

###6. Kết quả kiểm chứng thực tế (Validation PoC)

* **Tại máy Kali Linux:** Ngay sau khi gõ lệnh Hydra được khoảng 5 giây, màn hình quét lập tức bị khựng lại và báo lỗi `Connection refused` hoặc `Connection timed out`. Máy Kali hoàn toàn bị mất kết nối tới mục tiêu.
* **Tại máy chủ Wazuh Manager:** Chui vào container manager kiểm tra file log thực thi phản ứng bằng lệnh:
```bash
sudo docker exec -it single-node-wazuh.manager-1 tail -n 5 /var/ossec/logs/active-responses.log

```


Màn hình hiển thị dòng log xác nhận: `active-response/bin/firewall-drop add - 192.168.71.130` (Đã thêm lệnh chặn IP của Kali Linux thành công).
* **Trên Web Dashboard:** Phân hệ *Threat Hunting* hiển thị một Alert màu đỏ đạt mức **Level 10**, gắn nhãn kỹ thuật `MITRE T1110` kèm theo thông tin chi tiết của IP tấn công.

