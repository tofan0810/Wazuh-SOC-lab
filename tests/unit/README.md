# 🧪 Detection Engineering Unit Test Suite

> **Phân hệ:** Kiểm thử Đơn vị & Đảm bảo Chất lượng Luật Phát hiện (Detection-as-Code QA)  
> **Target Files:** `manager/rules/local_rules.xml`, `manager/rules/local_decoder.xml`, `manager/docker/ossec.conf`, `endpoint/config/sysmon-config.xml`, `manager/dashboard/*.ndjson`, `manager/suricata/*`

---

## 📌 Tổng Quan
Thư mục này chứa bộ kiểm thử đơn vị tự động hóa bảo vệ hệ thống SIEM Wazuh khỏi các sự cố cú pháp XML, xung đột định danh Rule ID, biểu thức chính quy (Regex) không hợp lệ, hoặc vi phạm chính sách an ninh bảo mật. Bộ test này được tự động kích hoạt bởi **GitHub Actions CI/CD** (`.github/workflows/test.yml`) trong mỗi commit và Pull Request.

---

## 🛡️ Danh Mục 22 Tiêu Chí Kiểm Thử (22 Automated Checks)

| STT | Phương Thức Kiểm Thử | Mục Đích & Phạm Vi Xác Thực |
| :---: | :--- | :--- |
| 1 | `test_xml_files_well_formed` | Xác thực cú pháp XML chuẩn của `local_rules.xml`, `local_decoder.xml`, `ossec.conf` và `sysmon-config.xml`. Tránh crash `wazuh-analysisd`. |
| 2 | `test_rule_ids_are_unique_and_valid` | Đảm bảo tính duy nhất của mọi Rule ID và nằm trong dải số tùy biến hợp lệ (`>= 100000`). |
| 3 | `test_rule_levels_in_valid_range` | Cấp độ cảnh báo (Severity Level) nằm trong dải số tiêu chuẩn của Wazuh (`0–16`). |
| 4 | `test_mitre_attack_id_format` | Định dạng chuẩn MITRE ATT&CK (`Txxxx` hoặc kỹ thuật con `Txxxx.xxx`). |
| 5 | `test_brute_force_rule` | Quy tắc 100001 (Level 12, frequency=5, timeframe=60, if_matched_sid=60122, MITRE T1110). |
| 6 | `test_lfi_rule` | Quy tắc 100002 (Level 10, if_sid=31100, MITRE T1190, lọc chuỗi Directory Traversal). |
| 7 | `test_lfi_decoder_extracts_url` | Bộ giải mã `web-access-lfi` bóc tách đúng trường `url` từ Apache Access Logs. |
| 8 | `test_killchain_rules_present_and_configured` | Đầy đủ 4 giai đoạn MITRE Kill Chain: Rule 100004 (T1059.001), 100007 (T1548.002), 100006 (T1547.001), 100005 (T1003.001). |
| 9 | `test_hierarchical_suppression_rules` | Quy tắc ức chế phân cấp (Rule 100008, 100009, 100010) đạt Level 0, trỏ đúng Rule cha, áp dụng logic AND cho WinRM `socrunner`. |
| 10 | `test_decoder_and_rule_regexes_compile` | Tất cả regex trong `<decoder>` và `<field>` (PCRE2) biên dịch an toàn mà không phát sinh `re.error`. |
| 11 | `test_single_n8n_integration_block` | Duy nhất 1 khối tích hợp `<integration>` cho `custom-n8n` webhook trong `ossec.conf`. |
| 12 | `test_zero_secret_leakage_in_templates` | Đảm bảo `.env.example` và các tệp mẫu không chứa API keys thật (VirusTotal, Telegram, Jira, Passwords). |

---

## 🚀 Hướng Dẫn Thực Thi

### 1. Sử dụng Built-in unittest runner (Không cần cài đặt thư viện ngoài):
```powershell
python -m unittest discover -s tests/unit -v
```

### 2. Sử dụng pytest kết hợp đo lường độ bao phủ (Coverage):
```powershell
pytest tests/unit/ -v --cov=tests/unit --cov-report=term-missing
```

### 3. Tự động hóa qua GitHub Actions:
Mọi thao tác đẩy mã nguồn (push/PR) lên branch `main` tác động vào `manager/`, `endpoint/`, `tests/` đều sẽ tự động kích hoạt workflow `.github/workflows/test.yml` trên runner Ubuntu đám mây.
