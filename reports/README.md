# 📋 Technical Reports & Phase Documentation Hub

Thư mục lưu trữ toàn bộ các báo cáo kỹ thuật, minh chứng thực nghiệm (PoC) và ảnh chụp màn hình ghi nhận qua **10 giai đoạn phát triển (Phase 1 – 10)** của dự án **Wazuh SOC & SOAR Lab**.

---

## 📌 Mục Lục Các Báo Cáo Triển Khai (Phase 1 – 10)

| Giai Đoạn | Tên Báo Cáo Kỹ Thuật | Nội Dung Trọng Tâm |
| :---: | :--- | :--- |
| **Phase 1** | [`Phase-1_Infrastructure-Deployment.md`](Phase-1_Infrastructure-Deployment.md) | Triển khai hạ tầng 3 máy ảo, cài đặt Wazuh All-in-One trên Docker, kernel hardening và kiểm thử kết nối mạng. |
| **Phase 2** | [`Phase-2_Agent-Sysmon-Configuration.md`](Phase-2_Agent-Sysmon-Configuration.md) | Cài đặt Wazuh Agent trên Windows 10, tích hợp Microsoft Sysmon v15.2, cấu hình FIM thời gian thực. |
| **Phase 3** | [`Phase-3/README.md`](Phase-3/README.md) | 3 Kịch bản tấn công thực tế: RDP Brute-force (Scenario 1), Web Apache LFI (Scenario 2), Full Kill Chain (Scenario 3). |
| **Phase 4** | [`Phase-4/README.md`](Phase-4/README.md) | Bộ kịch bản tự động hóa kiểm thử hồi quy (Regression Testing) từ Kali Attacker tới Windows Endpoint và SIEM. |
| **Phase 5** | [`Phase-5/README.md`](Phase-5/README.md) | Tự động hóa SOAR n8n, ChatOps Telegram 2 chiều, 1-Click Host Isolation an toàn, tích hợp Jira Cloud và Instant Rollback 5s. |
| **Phase 6** | [`Phase-6/README.md`](Phase-6/README.md) | DevSecOps CI/CD Pipeline trên GitHub Actions, tự động kiểm thử cú pháp XML Rules, Regex, MITRE format (22/22 PASS). |
| **Phase 7** | [`Phase-7/README.md`](Phase-7/README.md) | Xây dựng Executive Incident Dashboard trên OpenSearch Dashboards (Port 443) với 7 Visualizations chuyên nghiệp. |
| **Phase 8** | [`Phase-8/README.md`](Phase-8/README.md) | Detection-as-Code SSOT với ngôn ngữ Sigma YAML, bộ biên dịch SigWaz Engine và cơ chế Zero-Drift Enforcement. |
| **Phase 9** | [`Phase-9/README.md`](Phase-9/README.md) | Tích hợp Suricata 8.0.7 NIDS bắt luồng mạng thô trên `ens33`, stream EVE JSON trực tiếp vào Wazuh và n8n SOAR. |
| **Phase 10** | [`Phase-10/README.md`](Phase-10/README.md) | Công nghệ bẫy mồi đa tầng (Canary File, Honey-Account, FTP Decoy) 0% cảnh báo giả và tự động nén chứng cứ DFIR gửi Jira. |
