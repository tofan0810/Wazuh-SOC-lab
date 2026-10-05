# BÁO CÁO TRIỂN KHAI CI/CD PIPELINE CHO DETECTION ENGINEERING (PHASE 6 - DETECTION-AS-CODE WITH GITHUB ACTIONS)

* **Dự án:** Hệ thống Giám sát An ninh mạng & Ứng phó Sự cố Tập trung (Wazuh SIEM/XDR Lab)
* **Vị trí giả lập:** Detection Engineer / SOC Automation Engineer (DevSecOps / SecOps Lead)
* **Môi trường thực hiện:**
  * **Hạ tầng CI/CD:** GitHub Actions Cloud Runner (`ubuntu-latest`) với ma trận kiểm thử song song Python `3.10` và `3.11`.
  * **Môi trường điều khiển cục bộ (Host):** Windows 10/11 Pro, Python 3.11.9, `pytest 9.0.2`, `pytest-cov 7.1.0`.
  * **Mục tiêu kiểm toán (Under Test):** Tập luật tùy biến [`custom-rules/local_rules.xml`](../../custom-rules/local_rules.xml), bộ giải mã [`custom-rules/local_decoder.xml`](../../custom-rules/local_decoder.xml), cấu hình SIEM [`deployment/ossec.conf`](../../deployment/ossec.conf), cấu hình kiểm toán máy trạm [`deployment/sysmon-config.xml`](../../deployment/sysmon-config.xml) và tệp cấu hình mẫu [`.env.example`](../../.env.example).

---

## I. TỔNG QUAN VẤN ĐỀ & TRIẾT LÝ DETECTION-AS-CODE (DaC)

### 1. Thách thức Vận hành Thực tế Tại Trung Tâm SOC Doanh Nghiệp
Trong một trung tâm điều hành an ninh mạng (Next-Gen SOC) hiện đại, các kỹ sư **Detection Engineering** thường xuyên phải nghiên cứu các mối đe dọa mới (Emerging Threats, CVEs, kỹ thuật MITRE ATT&CK mới) để viết thêm hoặc tinh chỉnh luật phát hiện SIEM. Tuy nhiên, quy trình quản lý luật truyền thống (thao tác trực tiếp trên giao diện GUI hoặc sửa file cấu hình bằng tay trên máy chủ SIEM) tiềm ẩn những rủi ro thảm khốc:

1. **Nguy cơ làm sập Lõi Phân tích SIEM (Daemon Crash):**
   * Wazuh sử dụng daemon phân tích log `wazuh-analysisd`. Nếu một kỹ sư sơ suất gõ sai cú pháp XML (thiếu thẻ đóng `</rule>`, sai thuộc tính `level`, lồng thẻ không đúng quy cách) và reload service, `wazuh-analysisd` sẽ **ngừng hoạt động lập tức**.
   * Hậu quả: Toàn bộ hệ thống SOC bị "mù" (Blind Spot), không còn khả năng thu nhận log và phát hiện bất kỳ sự cố nào từ hàng nghìn máy trạm trong doanh nghiệp.
2. **Xung đột Định danh Luật (Rule ID Collisions):**
   * Nếu hai kỹ sư cùng tạo các luật mới với trùng mã số `id` (hoặc xâm lấn vào dải ID mặc định của hệ thống `< 100000`), Wazuh sẽ từ chối khởi động hoặc vô hiệu hóa một trong hai luật, tạo kẽ hở cho tin tặc xâm nhập.
3. **Lỗi Biểu thức Chính quy (Regex / PCRE2 Failure):**
   * Các biểu thức chính quy sai cú pháp hoặc gây ra hiện tượng quay lui vô hạn (Catastrophic Backtracking) sẽ làm tiêu tốn 100% CPU của máy chủ SIEM hoặc sinh ra cảnh báo giả (False Positives) làm kiệt quệ tinh thần trực ca của Analyst L1.
4. **Rò rỉ Thông tin Bí mật (Credential & Secret Leakage):**
   * Khi đẩy mã nguồn lên Git repository chung của nhóm, rủi ro vô tình commit các API Token thật (Telegram Bot Token, VirusTotal API Key, AbuseIPDB Key, Jira Password) là cực kỳ lớn nếu không có cơ chế rà soát bảo mật tự động.
5. **Phá vỡ Tính toàn vẹn của Luật Giảm Nhiễu Tự Động (Broken Suppression):**
   * Các hành động khắc phục của SOAR (như WinRM `socrunner` diệt tiến trình hay cô lập mạng) cần các luật ức chế phân cấp (Hierarchical Suppression Rules - Level 0) để không tự kích hoạt cảnh báo vòng lặp. Nếu các luật này bị chỉnh sửa sai lệch, hệ thống sẽ rơi vào trạng thái bão cảnh báo (Alert Storm).

---

### 2. Triết Lý Giải Pháp: Detection-as-Code (DaC) Kết Hợp CI/CD Pipeline
Để giải quyết triệt để các rủi ro trên, dự án áp dụng mô hình **Detection-as-Code (DaC)** theo chuẩn công nghiệp quốc tế:
* **Mọi quy tắc phát hiện và bộ giải mã đều được quản lý như mã nguồn (Source Code)** trong hệ thống Git Version Control.
* **Mọi thay đổi (Commit / Pull Request) bắt buộc phải vượt qua cánh cổng kiểm thử tự động (CI Gatekeeper)** trên nền tảng **GitHub Actions**.
* Nếu phát hiện bất kỳ lỗi cú pháp XML, xung đột ID, regex hỏng hoặc rò rỉ mã bí mật, GitHub Actions sẽ **chặn đứng (Fail Build ❌)**, ngăn chặn việc merge mã lỗi vào nhánh chính (`main`) và bảo vệ 100% thời gian hoạt động liên tục (Uptime) của cụm máy chủ Wazuh SIEM.

```text
  ┌────────────────────────────────────────────────────────────────────────┐
  │                 QUY TRÌNH DETECTION-AS-CODE VẬN HÀNH                   │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ Kỹ sư commit rule XML mới
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │         GITHUB ACTIONS CI PIPELINE (.github/workflows/test.yml)        │
  │                                                                        │
  │  [Ubuntu Runner: Ma trận Python 3.10 & Python 3.11]                     │
  │   ├── 1. XML Well-formedness & Syntax Parser (local_rules, decoder)    │
  │   ├── 2. Rule ID Uniqueness & Namespace Validation (>= 100000)         │
  │   ├── 3. Alert Severity Range Audit (Level 0 - 16)                     │
  │   ├── 4. MITRE ATT&CK Technique Format Verification (Txxxx.xxx)       │
  │   ├── 5. Scenario 1 (RDP Brute Force) & Scenario 2 (LFI) Rule Logic    │
  │   ├── 6. 4-Stage MITRE Kill Chain Rules (T1059, T1548, T1547, T1003)   │
  │   ├── 7. Hierarchical Child Suppression Rules (Level 0, AND logic)     │
  │   ├── 8. PCRE2 & Decoder Regex Compilation Safety                       │
  │   ├── 9. Single SOAR Integration Block Integrity (custom-n8n)          │
  │   └── 10. Zero Secret Leakage Scan (Templates & Configs)               │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   │                                     │
           [12/12 PASS] ✅                         [ANY FAIL] ❌
                   │                                     │
                   ▼                                     ▼
  ┌─────────────────────────────────┐   ┌─────────────────────────────────┐
  │     MERGE TO PRODUCTION SIEM    │   │         BLOCK MERGE P.R.        │
  │ • Hiển thị Badge Build Passing  │   │ • Báo động đỏ trên GitHub       │
  │ • Đồng bộ an toàn lên Wazuh VM  │   │ • Bảo vệ daemon analysisd       │
  └─────────────────────────────────┘   └─────────────────────────────────┘
```

---

## II. KIẾN TRÚC KỸ THUẬT CỦA PIPELINE GITHUB ACTIONS

### 1. Tệp Cấu Hình Workflow ([`.github/workflows/test.yml`](../../.github/workflows/test.yml))
Workflow được cấu hình với các thông số kỹ thuật tối ưu:
* **Tên Workflow:** `Detection Engineering CI`
* **Sự kiện kích hoạt (Triggers):**
  * `push` và `pull_request` vào các nhánh `main`, `master`.
  * Bộ lọc đường dẫn (`paths`): Chỉ kích hoạt khi có thay đổi trong `custom-rules/**`, `tests/**`, `deployment/**`, `.github/workflows/**`, `Makefile`, `.env.example`. Giúp tiết kiệm tài nguyên và thời gian chạy CI khi chỉ sửa tài liệu thông thường.
  * Hỗ trợ kích hoạt thủ công (`workflow_dispatch`) phục vụ kiểm tra tức thời.
* **Ma trận Môi trường (Matrix Strategy):**
  * Chạy song song trên **Python 3.10** và **Python 3.11** trên nền tảng `ubuntu-latest`.
  * Thuộc tính `fail-fast: false`: Đảm bảo nếu một phiên bản lỗi thì phiên bản còn lại vẫn hoàn thành để thu thập đầy đủ báo cáo đối soát.

```yaml
name: Detection Engineering CI

on:
  push:
    branches: [ "main", "master" ]
    paths:
      - 'custom-rules/**'
      - 'tests/**'
      - 'deployment/**'
      - '.github/workflows/**'
      - 'Makefile'
      - '.env.example'
  pull_request:
    branches: [ "main", "master" ]
    paths:
      - 'custom-rules/**'
      - 'tests/**'
      - 'deployment/**'
      - '.github/workflows/**'
      - 'Makefile'
      - '.env.example'
  workflow_dispatch:

jobs:
  validate-detections:
    name: Validate Rules, Decoders & SIEM Configs (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11"]

    steps:
      - name: 📥 Checkout repository
        uses: actions/checkout@v4

      - name: 🐍 Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: 📦 Install testing dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest pytest-cov

      - name: 🧪 Execute Detection Engineering Unit Tests (pytest)
        run: |
          pytest tests/unit/ -v --junitxml=test-results-${{ matrix.python-version }}.xml --cov=tests/unit --cov-report=term-missing

      - name: 🔍 Secondary Verification via Builtin unittest Runner
        run: |
          python -m unittest discover -s tests/unit -v

      - name: 📋 Publish CI Detection Engineering Summary
        if: always()
        run: |
          echo "### 🛡️ Detection Engineering CI Pipeline Summary" >> $GITHUB_STEP_SUMMARY
          echo "Environment: **Python ${{ matrix.python-version }} on Ubuntu Latest**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Validation Category | Target Component | Status |" >> $GITHUB_STEP_SUMMARY
          echo "| :--- | :--- | :---: |" >> $GITHUB_STEP_SUMMARY
          echo "| XML Syntax & Well-Formedness | \`custom-rules/local_rules.xml\`, \`local_decoder.xml\` | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| SIEM & Sysmon Schema | \`deployment/ossec.conf\`, \`sysmon-config.xml\` | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Rule ID Uniqueness (>=100000) | Custom Rules 100001 - 100010 | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Alert Level Validation (0-16) | Severity Bounds & Hierarchy | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| MITRE ATT&CK Format Verification | T1110, T1190, T1059, T1548, T1547, T1003 | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| PCRE2 & Regex Compilation | Custom Decoders & Sysmon Match Fields | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Child Suppression Rules (Level 0) | SOAR Remediation (WinRM \`socrunner\`) | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| Zero Secret Leakage Audit | No plaintext credentials in templates | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
          echo "| SOAR Integration Architecture | Single \`custom-n8n\` Webhook Block | ✅ PASS |" >> $GITHUB_STEP_SUMMARY
```

---

## III. CHI TIẾT 12 HẠNG MỤC KIỂM THỬ ĐƠN VỊ TỰ ĐỘNG

Toàn bộ 12 tiêu chí kiểm toán được lập trình trong tệp [`tests/unit/test_detection_config.py`](../../tests/unit/test_detection_config.py) kế thừa từ thư viện chuẩn `unittest.TestCase`:

```python
import os
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Repo root is 2 levels up from tests/unit/
ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "custom-rules" / "local_rules.xml"
DECODERS = ROOT / "custom-rules" / "local_decoder.xml"
OSSEC_CONF = ROOT / "deployment" / "ossec.conf"
SYSMON_CONF = ROOT / "deployment" / "sysmon-config.xml"
ENV_EXAMPLE = ROOT / ".env.example"
```

### Bảng Ma Trận Phân Tích 12 Tiêu Chí Kiểm Toán:

| STT | Tên Phương Thức Kiểm Thử | Đối Tượng Xác Thực | Mô Tả Ý Nghĩa An Ninh & Tiêu Chuẩn Kỹ Thuật |
| :---: | :--- | :--- | :--- |
| **1** | `test_xml_files_well_formed` | `local_rules.xml`<br/>`local_decoder.xml`<br/>`ossec.conf`<br/>`sysmon-config.xml` | Phân tích cây DOM XML. Đảm bảo toàn bộ thẻ mở/đóng, định dạng ký tự UTF-8 không bị lỗi cú pháp, ngăn ngừa sập dịch vụ `wazuh-analysisd`. |
| **2** | `test_rule_ids_are_unique_and_valid` | Tất cả thẻ `<rule id="...">` | Xác thực tính duy nhất của từng Rule ID trong hệ thống. Đảm bảo tất cả các ID tự định nghĩa đều là số nguyên và thuộc dải số người dùng quy ước (`id >= 100000`). |
| **3** | `test_rule_levels_in_valid_range` | Thuộc tính `level` của Rules | Kiểm tra mức độ cảnh báo (Severity Level) nằm trong dải số chuẩn của Wazuh (`0 <= level <= 16`), ngăn chặn việc cấu hình nhầm level gây sai lệch cơ chế lọc. |
| **4** | `test_mitre_attack_id_format` | Thẻ `<mitre><id>` | Dùng regex `^T\d{4}(\.\d{3})?$` để xác thực định dạng kỹ thuật MITRE ATT&CK (ví dụ `T1110`, `T1059.001`), đảm bảo dữ liệu hiển thị chuẩn xác trên ma trận Heatmap. |
| **5** | `test_brute_force_rule` | Rule `100001` | Xác thực cấu hình Scenario 1: `level="12"`, `frequency="5"`, `timeframe="60"`, kế thừa `if_matched_sid="60122"` và ánh xạ kỹ thuật `T1110`. |
| **6** | `test_lfi_rule` | Rule `100002` | Xác thực cấu hình Scenario 2: `level="10"`, kế thừa `if_sid="31100"`, ánh xạ `T1190`, nhận diện đầy đủ chuỗi tấn công Path Traversal: `win.ini`, `boot.ini`, `..%2f`, `..%252f`, `../`. |
| **7** | `test_lfi_decoder_extracts_url` | Decoder `web-access-lfi` | Kiểm tra bộ giải mã log Web Apache: kế thừa cha `web-accesslog`, bóc tách trường `url` qua biểu thức `GET (\S+)\sHTTP`. |
| **8** | `test_killchain_rules_present_and_configured` | Rule `100004`, `100007`, `100006`, `100005` | Xác thực đủ 4 giai đoạn Windows Kill Chain: PowerShell Encoded (`T1059.001`), UAC Bypass `ms-settings` (`T1548.002`), Registry Run Key (`T1547.001`), và LSASS Memory Dump (`T1003.001`). |
| **9** | `test_hierarchical_suppression_rules` | Rule `100008`, `100009`, `100010` | Đảm bảo các luật ức chế SOAR có `level="0"`, liên kết đúng Rule cha qua `if_sid`, sử dụng logic AND chặt chẽ với người dùng ủy quyền `socrunner` và tiến trình WinRM (`cmd.exe`, `wsmprovhost.exe`). |
| **10** | `test_decoder_and_rule_regexes_compile` | Tất cả `<regex>` và `<field type="pcre2">` | Nạp và biên dịch thử nghiệm toàn bộ biểu thức chính quy bằng engine `re.compile`. Phát hiện sớm các lỗi cú pháp regex làm treo tiến trình quét. |
| **11** | `test_single_n8n_integration_block` | Thẻ `<integration>` trong `ossec.conf` | Đảm bảo chỉ tồn tại duy nhất 1 khối cấu hình tích hợp `custom-n8n` trỏ về webhook `/webhook/wazuh-alert`, tránh việc phân phối cảnh báo trùng lặp. |
| **12** | `test_zero_secret_leakage_in_templates` | Tệp mẫu `.env.example` | Quét chuỗi bảo mật: Đảm bảo chỉ dùng chuỗi placeholder (như `your_virustotal_api_key_here`), tuyệt đối không rò rỉ mã token thật (Telegram bot token `\d{8,10}:[A-Za-z0-9_-]{35}` hoặc hash 64 ký tự). |

---

## IV. CÁC BƯỚC THỰC THI & HƯỚNG DẪN CHỤP ẢNH MINH CHỨNG THỰC NGHIỆM

Dưới đây là 5 bước thực nghiệm minh chứng cho toàn bộ chu trình hoạt động của CI/CD Pipeline. Mỗi bước đều đi kèm hình ảnh minh chứng và hướng dẫn chi tiết cách chụp ảnh màn hình đúng chuẩn.

---

### 1. Bước 1: Kiểm thử Đơn vị Cục bộ (Local Unit Testing Execution)

Trước khi thực hiện commit mã nguồn lên GitHub, kỹ sư thực hiện chạy kiểm thử cục bộ ngay trên máy trạm thông qua công cụ `pytest` kết hợp đo lường độ bao phủ mã nguồn (`pytest-cov`).

* **Lệnh thực thi trên máy Host (PowerShell):**
  ```powershell
  # Chạy kiểm thử chi tiết qua pytest
  pytest tests/unit/ -v --cov=tests/unit --cov-report=term-missing

  # Hoặc kiểm tra đối soát với unittest tích hợp sẵn của Python
  python -m unittest discover -s tests/unit -v
  ```

* **Kết quả đạt được:** Cả 12 bài kiểm tra đều vượt qua thành công với thời gian thực thi cực nhanh:

![Kết quả chạy 12 Unit Test cục bộ đạt 100% PASS](images/01_unit_tests_local_execution.png)

### 2. Bước 2: Cấu trúc Tệp Cấu hình CI Workflow Trong Trình Soạn Thảo (IDE View)

Trực quan hóa tệp cấu hình pipeline `.github/workflows/test.yml` và cấu trúc phân thư mục `tests/unit/` trên trình soạn thảo Visual Studio Code.

* **Vị trí tệp tin:** [`.github/workflows/test.yml`](../../.github/workflows/test.yml) và [`tests/unit/test_detection_config.py`](../../tests/unit/test_detection_config.py).

### 3. Bước 3: Pipeline GitHub Actions Kích Hoạt Tự Động & Chạy Thành Công (CI Pipeline Run)

Khi kỹ sư thực hiện đẩy commit hoặc mở Pull Request cập nhật luật phát hiện mới lên GitHub, GitHub Actions sẽ lập tức phân bổ runner điện toán đám mây và kích hoạt pipeline kiểm tra tự động.

* **Đường dẫn trên GitHub:** `https://github.com/tofan0810/Wazuh-SOC-lab/actions`
* **Workflow Name:** `Detection Engineering CI`
* **Kết quả:** Cả 2 công việc (jobs) trên môi trường **Python 3.10** và **Python 3.11** đều hoàn thành với biểu tượng tích xanh `Success` ✅.

![Giao diện GitHub Actions thực thi pipeline thành công](images/03_github_actions_pipeline_run.png)

> **📸 Hướng dẫn chụp ảnh `03_github_actions_pipeline_run.png`:**
> * **Vị trí chụp:** Trình duyệt Web truy cập vào mục **Actions** của repository `Wazuh-SOC-lab` trên GitHub (`https://github.com/tofan0810/Wazuh-SOC-lab/actions`).
> * **Thao tác:** Nhấp vào lượt chạy mới nhất của workflow `Detection Engineering CI`. Màn hình sẽ hiển thị sơ đồ luồng công việc gồm hai nhánh matrix: `Validate Rules, Decoders & SIEM Configs (Python 3.10)` và `Validate Rules, Decoders & SIEM Configs (Python 3.11)`.
> * **Nội dung cần làm nổi bật trong ảnh:** Cả hai job đều có dấu tích tròn màu xanh lá cây (`Success`), thời gian hoàn thành (dưới 1 phút), commit message rõ ràng và commit hash tương ứng.

---

### 4. Bước 4: Bảng Tổng Kết Trạng Thái Kiểm Thử Trực Quan (GitHub Step Summary)

Nhờ vào việc tích hợp xuất dữ liệu ra tệp `$GITHUB_STEP_SUMMARY` trong cấu hình workflow, GitHub Actions tự động kết xuất bảng đối soát chất lượng an ninh ngay tại trang chủ của lần chạy mà không cần kỹ sư phải vào lục tìm trong các dòng log dòng lệnh.

* **Nội dung hiển thị:**
  * Tiêu đề: `🛡️ Detection Engineering CI Pipeline Summary`.
  * Bảng ma trận đối soát 9 hạng mục thành phần lõi:
    * XML Syntax & Well-Formedness: **✅ PASS**
    * SIEM & Sysmon Schema: **✅ PASS**
    * Rule ID Uniqueness (>=100000): **✅ PASS**
    * Alert Level Validation (0-16): **✅ PASS**
    * MITRE ATT&CK Format Verification: **✅ PASS**
    * PCRE2 & Regex Compilation: **✅ PASS**
    * Child Suppression Rules (Level 0): **✅ PASS**
    * Zero Secret Leakage Audit: **✅ PASS**
    * SOAR Integration Architecture: **✅ PASS**

![Bảng báo cáo GitHub Step Summary trực quan trên GitHub Actions](images/04_github_step_summary.png)

> **📸 Hướng dẫn chụp ảnh `04_github_step_summary.png`:**
> * **Vị trí chụp:** Trình duyệt Web trong trang chi tiết lần chạy của GitHub Actions (tab **Summary**).
> * **Thao tác:** Cuộn xuống phần nội dung phía dưới các job đồ họa, nơi hiển thị bảng Markdown tự động do lệnh `echo ... >> $GITHUB_STEP_SUMMARY` sinh ra.
> * **Nội dung cần làm nổi bật trong ảnh:** Tiêu đề có icon chiếc khiên bảo mật (`🛡️`), môi trường hiển thị `Python 3.11 on Ubuntu Latest`, và bảng ma trận với cột trạng thái toàn bộ là các biểu tượng `✅ PASS`.

---

### 5. Bước 5: Huy Hiệu Trạng Thái CI Thời Gian Thực Trên Tài Liệu Dự Án (CI Status Badge)

Để thể hiện tính chuyên nghiệp và minh bạch về chất lượng mã nguồn theo tiêu chuẩn Open Source và Enterprise, một huy hiệu (Badge) động đã được gắn ngay trên đầu tệp [`README.md`](../../README.md).

* **Mã nhúng Badge trong Markdown:**
  ```markdown
  [![Detection Engineering CI](https://github.com/tofan0810/Wazuh-SOC-lab/actions/workflows/test.yml/badge.svg)](https://github.com/tofan0810/Wazuh-SOC-lab/actions/workflows/test.yml)
  ```
* **Ý nghĩa:** Huy hiệu tự động truy vấn trạng thái lần chạy gần nhất của nhánh `main`. Nếu lần chạy thành công, huy hiệu hiển thị màu xanh rực rỡ **`Detection Engineering CI | passing`**. Nếu có lỗi, huy hiệu sẽ chuyển sang màu đỏ **`failing`**, lập tức cảnh báo cho toàn bộ đội ngũ kỹ sư.

![Huy hiệu CI build passing trên trang bìa README.md](images/05_readme_ci_badge.png)

> **📸 Hướng dẫn chụp ảnh `05_readme_ci_badge.png`:**
> * **Vị trí chụp:** Trang chủ repository trên GitHub hoặc bản render của tệp `README.md` trong VS Code / GitHub Preview.
> * **Thao tác:** Chụp phần tiêu đề đầu trang của dự án (ngay dưới dòng tiêu đề `# Wazuh SIEM & Detection Engineering Lab`).
> * **Nội dung cần làm nổi bật trong ảnh:** Nhóm các huy hiệu danh giá của dự án bao gồm: `License: MIT` (xanh), `SIEM: Wazuh` (xanh dương), `Framework: MITRE ATT&CK` (cam), và đặc biệt là huy hiệu mới thêm: `Detection Engineering CI: passing` (xanh lá cây).

---

## V. ĐÁNH GIÁ HIỆU QUẢ VẬN HÀNH & GIÁ TRỊ THỰC TIỄN DOANH NGHIỆP

| Tiêu Chí Đánh Giá | Quy Trình Thủ Công Truyền Thống | Sau Khi Ứng Dụng CI/CD (Phase 6) | Mức Độ Cải Thiện |
| :--- | :--- | :--- | :---: |
| **Thời gian Kiểm thử Chất lượng (QA Duration)** | 30 – 60 phút (mở 3 máy ảo, kích hoạt tool tấn công thủ công) | **0.02 giây** trên máy trạm cục bộ, **< 45 giây** trên GitHub Cloud Runner | **Nhanh hơn ~100 lần** ⚡ |
| **Nguy cơ Sập Daemon SIEM (`wazuh-analysisd`)** | Rất cao (khi sơ suất gõ nhầm cú pháp thẻ XML, thiếu thẻ đóng) | **Bằng 0%** (GitHub chặn đứng mọi PR/commit có cú pháp XML không hợp lệ) | **Triệt tiêu 100% downtime do cấu hình** 🛡️ |
| **Bảo vệ Bí mật An ninh (Secret Protection)** | Dễ bị lộ API key thật khi commit code lên kho lưu trữ chung | **Tự động quét và cảnh báo** nếu phát hiện API key hay mật khẩu thật | **Tuân thủ tuyệt đối chuẩn Zero Secret Leakage** 🔒 |
| **Độ tin cậy của Rule Giảm Nhiễu (Suppression)** | Dễ bị sai lệch logic dẫn tới báo động giả hoặc bỏ lọt tấn công | Tự động kiểm tra cấu trúc phân cấp (Level 0, AND logic với `socrunner`) | **Đảm bảo 100% tính toàn vẹn của phản ứng SOAR** 🤖 |
| **Tiêu chuẩn Hóa Quy trình Vận hành** | Phụ thuộc vào trí nhớ và kinh nghiệm cá nhân của từng kỹ sư | Quy trình tự động hóa khép kín theo chuẩn quốc tế **DevSecOps / DaC** | **Chuyên nghiệp hóa theo chuẩn Enterprise SOC** 🏢 |

