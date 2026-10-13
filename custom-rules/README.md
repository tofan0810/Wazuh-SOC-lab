# 📜 Custom Rules & Decoders (Detection-as-Code)

Thư mục lưu trữ toàn bộ các bộ giải mã (decoders) và tập luật phát hiện tùy chỉnh của hệ thống Wazuh SIEM, được quản lý theo phương pháp luận **Detection-as-Code**.

---

## 🗂️ Cấu Trúc Thư Mục

```text
custom-rules/
├── sigma/             # Kho luật chuẩn hóa Sigma YAML (Single Source of Truth - SSOT)
│   ├── win_*.yml      # Các luật phát hiện Endpoint Windows (Sysmon & Security EVTX)
│   ├── net_*.yml      # Các luật phát hiện Network Suricata NIDS
│   └── README.md      # Hướng dẫn chi tiết quy chuẩn phát hiện Sigma
├── local_decoder.xml  # Bộ giải mã tùy chỉnh bóc tách log Apache Web Server
└── local_rules.xml    # Tập luật XML tích hợp sẵn (tự động biên dịch từ Sigma YAML qua SigWaz Compiler)
```

---

## 🔍 Dải Luật Phát Hiện Chính (Rule ID Namespace)

Toàn bộ quy tắc tùy chỉnh được cấp phát trong dải số an toàn `100000 - 100099`:
* **Rule 100001:** RDP Brute Force Detection (Event ID 4625)
* **Rule 100002:** Apache Web LFI / Path Traversal Detection
* **Rule 100004 - 100007:** Sysmon Multi-Stage Kill Chain (PowerShell, LSASS Dump, Run Key, UAC Bypass)
* **Rule 100008 - 100010:** Luật ức chế phân cấp (Hierarchical Level 0) cho tài khoản SOAR `socrunner`
* **Rule 100011 - 100013:** Suricata NIDS Events (Nmap SYN scan, LFI on wire, Scanners)
* **Rule 100014 - 100016:** Bẫy mồi Deception (Honey-File SACL 4663, Honey-Account 4625, Decoy 21)

---

## ⚡ Lệnh Biên Dịch & Chống Lệch Pha (Zero-Drift)
```powershell
# Kiểm tra đồng bộ giữa Sigma YAML và XML
python scripts/sigma_compiler.py --check

# Biên dịch lại từ Sigma YAML sang local_rules.xml
python scripts/sigma_compiler.py
```
