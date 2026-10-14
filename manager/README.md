# 🛡️ Wazuh Manager, NIDS & SOAR Provisioning Package (Ubuntu Server)

Thư mục đóng gói toàn diện các cấu hình container, bộ luật SIEM, NIDS Suricata và quy trình điều phối SOAR cho máy chủ **Ubuntu Server 22.04 LTS (`192.168.71.128`)**.

---

## ⚡ HƯỚNG DẪN TRIỂN KHAI 2 BƯỚC (QUICKSTART)

### Bước 1: Cài đặt công cụ nền tảng (Người dùng cài trước)
Trên máy chủ Ubuntu Server mới, mở terminal và thực thi lệnh cài đặt các gói hệ thống cần thiết:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin suricata jq python3-pip
```

---

### Bước 2: Chạy Script Master Thiết Lập Của Lab (1-Click Setup)
Di chuyển vào thư mục `manager/` và thực thi:

```bash
chmod +x setup_manager.sh
sudo ./setup_manager.sh
```

**Script `setup_manager.sh` sẽ tự động thực hiện 100% các công việc còn lại:**
1. ✅ Tự động chỉnh tham số Kernel: `sysctl -w vm.max_map_count=262144` và ghi vào `/etc/sysctl.conf` (đảm bảo Wazuh Indexer / OpenSearch không bị crash).
2. ✅ Khởi chạy cụm Docker Wazuh SIEM All-in-One (Manager, Indexer, Dashboard) và n8n SOAR (Port 5678).
3. ✅ Bơm bộ luật tùy chỉnh `rules/local_rules.xml` (Rule 100001 - 100016), `rules/local_decoder.xml` và script `soar/custom-n8n.py` trực tiếp vào container Wazuh Manager.
4. ✅ Kích hoạt Suricata 8.x NIDS trên card mạng `ens33` (Promiscuous mode) và cấu hình stream log `eve.json` vào Wazuh.
5. ✅ Khởi chạy tiến trình nền `soar/telegram_bridge.py` để tiếp nhận phản hồi từ các nút bấm ChatOps Telegram.
6. ✅ Xuất các địa chỉ truy cập Dashboard và n8n điều khiển.

*Sau khi cụm container khởi động hoàn toàn (~1 phút), bạn nạp Executive Dashboard bằng lệnh:*
```bash
python3 dashboard/import_dashboard.py
```

---

## 🗂️ Cấu Trúc Thư Mục `manager/`

```text
manager/
├── README.md                      # Hướng dẫn triển khai máy chủ Ubuntu SIEM/SOAR
├── setup_manager.sh               # Script master 1-Click tự động hóa toàn bộ máy chủ
├── docker/
│   ├── docker-compose.yml         # Cụm Wazuh Manager, Indexer, Dashboard (Port 443)
│   ├── docker-compose-n8n.yml     # Container n8n Automation Engine (Port 5678)
│   ├── ossec.conf                 # Cấu hình trung tâm Wazuh Manager & Webhook integration
│   └── .env.example               # Mẫu cấu hình API keys an toàn (Zero Secret Leakage)
├── rules/
│   ├── local_rules.xml            # Bộ luật Wazuh XML compiled chuẩn (Rule 100001 - 100016)
│   ├── local_decoder.xml          # Bộ giải mã tùy biến cho Apache Web Access Log
│   ├── sigma/                     # Kho luật Sigma YAML SSOT (9 quy tắc phát hiện)
│   └── README.md                  # Hướng dẫn quản trị luật Detection-as-Code
├── suricata/
│   ├── suricata.yaml              # Cấu hình capture ens33 & stream eve.json
│   ├── local.rules                # 4 Signatures NIDS (Nmap SYN, LFI, Scanners, RDP)
│   └── setup_suricata.sh          # Script tối ưu card mạng & cài đặt Suricata service
├── soar/
│   ├── workflows/                 # 3 Workflows JSON chuẩn hóa của n8n
│   ├── custom-n8n.py              # Script bóc tách IoC & dispatch alert sang n8n
│   ├── telegram_bridge.py         # Long-polling daemon nhận callback tương tác WinRM
│   └── restart_bridge.sh          # Script hỗ trợ restart daemon
└── dashboard/
    ├── soc_lab_executive_dashboard.ndjson # 7 Visualizations chuyên nghiệp trên OpenSearch
    └── import_dashboard.py                # Script nạp 1-click qua OpenSearch REST API
```
