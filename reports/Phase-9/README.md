# 🌐 Phase 9: Giám Sát Mạng Sâu Suricata NIDS (XDR Integration)

Thư mục lưu trữ báo cáo kỹ thuật và minh chứng của **Phase 9**, mở rộng kiến trúc từ SIEM/EDR sang **XDR** thông qua việc tích hợp hệ thống phát hiện xâm nhập mạng **Suricata 8.0.7 NIDS**.

---

## 📌 Báo Cáo Kỹ Thuật Chính
* **Tài liệu chi tiết:** [`Phase-9_Suricata-NIDS-XDR-Integration.md`](Phase-9_Suricata-NIDS-XDR-Integration.md)
* **Nội dung:**
  - Cài đặt và cấu hình Suricata 8.0.7 Stable trên Ubuntu Server, tối ưu card mạng `ens33` ở Promiscuous mode.
  - Xây dựng 4 Custom Signatures thực chiến (`local.rules`): Nmap Stealth SYN Scan (SID 2000001), Web LFI on Wire (SID 2000002), Vulnerability Scanners (SID 2000003), RDP Flood (SID 2000004).
  - Tích hợp luồng EVE JSON stream (`eve.json`) vào Wazuh Manager qua `<localfile>` json và chuyển tiếp cảnh báo tức thì tới n8n Telegram ChatOps.
