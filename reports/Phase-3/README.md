# ⚔️ Phase 3: Kịch Bản Tấn Công & Phát Hiện Thực Chiến

Thư mục lưu trữ các báo cáo chi tiết về 3 kịch bản tấn công và phát hiện thực nghiệm được triển khai từ máy Kali Linux (`192.168.71.130`) nhắm vào Windows 10 Endpoint (`192.168.71.129`).

---

## 📌 Danh Mục Báo Cáo Kịch Bản

| Báo Cáo Kỹ Thuật | Kỹ Thuật MITRE | Tóm Tắt Kịch Bản & Kết Quả |
| :--- | :---: | :--- |
| [`Phase-3_Scenario-1.md`](Phase-3_Scenario-1.md) | **T1110.001** | **RDP Brute Force:** Tấn công dò mật khẩu RDP bằng `xfreerdp`. Bắt Event ID 4625 qua Rule 100001, tự động kích hoạt `netsh` khóa IP kẻ tấn công 600s. |
| [`Phase-3_Scenario-2.md`](Phase-3_Scenario-2.md) | **T1190** | **Web LFI / Path Traversal:** Khai thác đọc trộm file `win.ini` qua Apache HTTP. Bắt qua Apache Access Log bằng Rule 100002, tự động chặn IP kẻ tấn công. |
| [`Phase-3_Scenario-3.md`](Phase-3_Scenario-3.md) | **T1059, T1548, T1547, T1003** | **Full Kill Chain:** Chuỗi 4 giai đoạn với Microsoft Sysmon (PowerShell Base64, UAC Bypass ms-settings, Registry Run Key, và LSASS Memory Dump). Tự động hóa qua `tests/e2e/scenario_full_killchain.py`. |
