# 🏛️ Architecture & Network Topology

Thư mục lưu trữ sơ đồ kiến trúc tổng thể, mô hình mạng kết nối và luồng dữ liệu tự động hóa của hệ thống **Wazuh SOC & SOAR Lab**.

---

## 📌 Danh Mục Tài Liệu & Sơ Đồ

| Tệp Tin | Định Dạng | Mô Tả Chức Năng |
| :--- | :---: | :--- |
| `Deployment and Containerization Architecture.png` | Image (PNG) | Sơ đồ triển khai hạ tầng 3 máy ảo độc lập, kiến trúc Docker container của Wazuh Cluster (Manager, Indexer, Dashboard) và n8n SOAR. |
| `Detection Pipeline & Active Response Sequence.png` | Image (PNG) | Sơ đồ tuần tự (Sequence Diagram) mô tả luồng bắt log từ Endpoint Sysmon/Suricata $\rightarrow$ Phân tích luật Wazuh $\rightarrow$ Kích hoạt Active Response $\rightarrow$ Dispatch sang n8n $\rightarrow$ Telegram ChatOps. |

---

## 🌐 Thông Số Mạng Các Nút (Lab IP Map)
* **Wazuh SIEM & SOAR Server:** `192.168.71.128` (Ubuntu Server 22.04 LTS)
* **Windows Endpoint Target:** `192.168.71.129` (Windows 10 Pro - Wazuh Agent & Sysmon)
* **Kali Attacker Node:** `192.168.71.130` (Kali Linux Rolling)
