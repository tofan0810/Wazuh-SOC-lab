# CÁC KỊCH BẢN TẤN CÔNG & PHÁT HIỆN THỰC CHIẾN (PHASE 3)

## 🔹 KỊCH BẢN 3: T1059.001 - PHÁT HIỆN THỰC THI POWERSHELL ĐỘC HẠI & GIÁM SÁT TIẾN TRÌNH

Kịch bản này là sự kết hợp sức mạnh tối đa giữa **Microsoft Sysmon v15.2** (vừa cài đặt ở Phase 2) và giải pháp SIEM để tóm gọn các kỹ thuật che giấu dòng lệnh của Hacker.

### 1. Kỹ thuật giả lập tấn công (Attack Simulation)

* Hacker sử dụng một câu lệnh PowerShell đã được mã hóa bằng thuật toán Base64 (`-EncodedCommand`) nhằm lẩn trốn các hệ thống quét chuỗi thông thường (Signature-based IDS), thực hiện hành vi tải file độc hại độc lập hoặc dump bộ nhớ:
* **Dòng lệnh độc hại chạy thực tế trên máy Windows 10 Victim:**
```cmd
powershell -NoP -NonI -W Hidden -EncodedCommand aXZleCAtVXJpIGh0dHBzOi8vZ29vZ2xlLmNvbQ==

```


*(Chuỗi băm Base64 phía sau khi giải mã ra chính là hành vi `Invoke-WebRequest` hướng tới Google mạng mà bạn đã thử nghiệm thành công).*

### 2. Thu thập Telemetry (Log Source)

* Toàn bộ hành vi được giám sát chặt chẽ thông qua kênh dẫn log Sysmon đã thông suốt ở Phase 2:
* **Sysmon Event ID 1 (Process Creation):** Ghi lại toàn bộ tham số che giấu trạng thái cửa sổ như `-W Hidden`, `-NoP`.
* **Sysmon Event ID 22 (DNS Query):** Ghi lại hành vi truy vấn phân giải tên miền ngay khi câu lệnh được thực thi.



### 3. Kỹ thuật viết Luật phát hiện tùy biến (Custom Rules Engineering)

Hành vi gọi PowerShell kèm theo các tham số ẩn danh là dấu hiệu nhận diện 99% của các cuộc tấn công Fileless Malware. Tiến hành viết bổ sung quy tắc giám sát vào tệp `/var/ossec/etc/rules/local_rules.xml` trên máy chủ Ubuntu:

```xml
<group name="sysmon,windows,powershell_attack,">
  <rule id="100003" level="12">
    <if_sid>61600</if_sid> <field name="win.eventdata.commandLine" type="pcre2">(?i)-EncodedCommand|-enc|-w\s+hidden|-nop</field>
    <description>CẢNH BÁO NGUY HIỂM: Phát hiện thực thi tiến trình PowerShell ngầm chứa tham số mã hóa Base64!</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

### 4. Kết quả kiểm chứng thực tế (Validation PoC)

* Bạn tiến hành chạy câu lệnh PowerShell mã hóa trên máy Windows 10.
* Đứng tại máy chủ Ubuntu, thực hiện lệnh "pháp y" quét trực tiếp file thô hệ thống để xác thực dữ liệu đã đổ về thành công:
```bash
sudo docker exec -it single-node-wazuh.manager-1 grep -i "EncodedCommand" /var/ossec/logs/alerts/alerts.json
```


* Màn hình nhả ra chuỗi JSON cấu trúc chi tiết, báo cáo chính xác mã **Rule ID: 100003**, định danh máy trạm phát sinh (`DESKTOP-A2AG7TR-NEW`) kèm theo trường dữ liệu vàng `win.eventdata.parentImage` chỉ rõ tiến trình cha gọi nó dậy là `cmd.exe`.
* Trên **Wazuh Dashboard**, sự kiện hiển thị ở mức độ nghiêm trọng **Level 12 (Critical Severity)**, làm nổi bật sơ đồ kỹ thuật tấn công mã hóa tiến trình của Hacker trên biểu đồ giám sát SOC.
