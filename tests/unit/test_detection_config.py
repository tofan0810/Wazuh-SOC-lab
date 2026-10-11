import sys
import os
import re
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Repo root is 2 levels up from tests/unit/
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RULES = ROOT / "custom-rules" / "local_rules.xml"
DECODERS = ROOT / "custom-rules" / "local_decoder.xml"
SIGMA_DIR = ROOT / "custom-rules" / "sigma"
OSSEC_CONF = ROOT / "deployment" / "ossec.conf"
SYSMON_CONF = ROOT / "deployment" / "sysmon-config.xml"
DASHBOARD_NDJSON = ROOT / "deployment" / "dashboards" / "soc_lab_executive_dashboard.ndjson"
SURICATA_RULES = ROOT / "deployment" / "suricata" / "local.rules"
SURICATA_YAML = ROOT / "deployment" / "suricata" / "suricata.yaml"
ENV_EXAMPLE = ROOT / ".env.example"


def parse_fragment(path: Path) -> ET.Element:
    return ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")


class DetectionConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules_root = ET.parse(RULES).getroot()
        cls.decoder_root = parse_fragment(DECODERS)
        cls.ossec_root = ET.parse(OSSEC_CONF).getroot()
        cls.sysmon_root = ET.parse(SYSMON_CONF).getroot()

        cls.rules = {r.attrib["id"]: r for r in cls.rules_root.findall("rule")}
        cls.decoders = {d.attrib["name"]: d for d in cls.decoder_root.findall("decoder")}

    # -------------------------------------------------------------------------
    # 1. XML Well-formedness & File Parsing
    # -------------------------------------------------------------------------
    def test_xml_files_well_formed(self):
        """Verifies that all core SIEM and endpoint XML files parse without syntax errors."""
        self.assertIsNotNone(self.rules_root)
        self.assertIsNotNone(self.decoder_root)
        self.assertIsNotNone(self.ossec_root)
        self.assertIsNotNone(self.sysmon_root)

    # -------------------------------------------------------------------------
    # 2. Rule IDs & Level Validation
    # -------------------------------------------------------------------------
    def test_rule_ids_are_unique_and_valid(self):
        """All rule IDs must be unique and in the custom range (>= 100000)."""
        ids = [r.attrib["id"] for r in self.rules_root.findall("rule")]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate rule ID found in local_rules.xml")
        for rid in ids:
            self.assertTrue(rid.isdigit(), f"Rule ID '{rid}' must be numeric")
            self.assertGreaterEqual(int(rid), 100000, f"Custom rule ID {rid} must be >= 100000")

    def test_rule_levels_in_valid_range(self):
        """Wazuh alert levels must be integers between 0 and 16."""
        for rid, rule in self.rules.items():
            level = rule.attrib.get("level")
            self.assertIsNotNone(level, f"Rule {rid} is missing 'level' attribute")
            self.assertTrue(level.isdigit(), f"Rule {rid} level must be integer, got {level}")
            self.assertIn(int(level), range(0, 17), f"Rule {rid} level {level} out of range (0-16)")

    # -------------------------------------------------------------------------
    # 3. MITRE ATT&CK Mapping Integrity
    # -------------------------------------------------------------------------
    def test_mitre_attack_id_format(self):
        """Every rule tagging MITRE ATT&CK must follow standard Txxxx or Txxxx.xxx format."""
        mitre_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for rid, rule in self.rules.items():
            mitre_id = rule.findtext("mitre/id")
            if mitre_id:
                self.assertRegex(
                    mitre_id,
                    mitre_pattern,
                    f"Rule {rid} has invalid MITRE ATT&CK ID format: {mitre_id}"
                )

    # -------------------------------------------------------------------------
    # 4. Scenario 1 & 2 Detections
    # -------------------------------------------------------------------------
    def test_brute_force_rule(self):
        """Scenario 1: Windows RDP Brute Force Detection (Rule 100001, T1110)."""
        rule = self.rules["100001"]
        self.assertEqual(rule.attrib["level"], "12")
        self.assertEqual(rule.attrib["frequency"], "5")
        self.assertEqual(rule.attrib["timeframe"], "60")
        self.assertEqual(rule.findtext("if_matched_sid"), "60122")
        self.assertEqual(rule.findtext("mitre/id"), "T1110")

    def test_lfi_rule(self):
        """Scenario 2: Web LFI / Path Traversal Detection (Rule 100002, T1190)."""
        rule = self.rules["100002"]
        self.assertEqual(rule.attrib["level"], "10")
        self.assertEqual(rule.findtext("if_sid"), "31100")
        self.assertEqual(rule.findtext("mitre/id"), "T1190")
        for indicator in ("win.ini", "boot.ini", "..%2f", "..%252f", "../"):
            self.assertIn(indicator, rule.findtext("match"))

    def test_lfi_decoder_extracts_url(self):
        """Scenario 2 Decoder: Extract URI from Apache HTTP access logs."""
        decoder = self.decoders["web-access-lfi"]
        self.assertEqual(decoder.findtext("parent"), "web-accesslog")
        self.assertEqual(decoder.findtext("order"), "url")
        self.assertEqual(decoder.findtext("regex"), r"GET (\S+)\sHTTP")

    # -------------------------------------------------------------------------
    # 5. MITRE Kill Chain 4-Stage Detection Rules
    # -------------------------------------------------------------------------
    def test_killchain_rules_present_and_configured(self):
        """Verifies all 4 stages of the MITRE ATT&CK Windows Kill Chain."""
        # Stage 1: PowerShell Execution (T1059.001)
        rule_ps = self.rules["100004"]
        self.assertEqual(rule_ps.attrib["level"], "12")
        self.assertEqual(rule_ps.findtext("mitre/id"), "T1059.001")

        # Stage 2: UAC Bypass via ms-settings (T1548.002)
        rule_uac = self.rules["100007"]
        self.assertEqual(rule_uac.attrib["level"], "12")
        self.assertEqual(rule_uac.findtext("mitre/id"), "T1548.002")

        # Stage 3: Persistence Run Key (T1547.001)
        rule_run = self.rules["100006"]
        self.assertEqual(rule_run.attrib["level"], "10")
        self.assertEqual(rule_run.findtext("mitre/id"), "T1547.001")

        # Stage 4: LSASS Memory Access (T1003.001)
        rule_lsass = self.rules["100005"]
        self.assertEqual(rule_lsass.attrib["level"], "12")
        self.assertEqual(rule_lsass.findtext("mitre/id"), "T1003.001")

    # -------------------------------------------------------------------------
    # 6. Hierarchical Child Suppression Rules (Level 0, True AND logic)
    # -------------------------------------------------------------------------
    def test_hierarchical_suppression_rules(self):
        """Verifies suppression rules for authorized SOAR remediation actions."""
        # Rule 100008: PowerShell Suppression
        suppress_ps = self.rules["100008"]
        self.assertEqual(suppress_ps.attrib["level"], "0")
        self.assertEqual(suppress_ps.findtext("if_sid"), "100004")
        fields_ps = {f.attrib["name"]: f.text for f in suppress_ps.findall("field")}
        self.assertIn("win.eventdata.user", fields_ps)
        self.assertIn("socrunner", fields_ps["win.eventdata.user"])
        self.assertIn("win.eventdata.parentImage", fields_ps)
        self.assertIn("cmd", fields_ps["win.eventdata.parentImage"])

        # Rule 100009: UAC Bypass Suppression
        suppress_uac = self.rules["100009"]
        self.assertEqual(suppress_uac.attrib["level"], "0")
        self.assertEqual(suppress_uac.findtext("if_sid"), "100007")
        fields_uac = {f.attrib["name"]: f.text for f in suppress_uac.findall("field")}
        self.assertIn("win.eventdata.user", fields_uac)
        self.assertIn("socrunner", fields_uac["win.eventdata.user"])

        # Rule 100010: Persistence Suppression
        suppress_persist = self.rules["100010"]
        self.assertEqual(suppress_persist.attrib["level"], "0")
        self.assertEqual(suppress_persist.findtext("if_sid"), "100006")
        fields_persist = {f.attrib["name"]: f.text for f in suppress_persist.findall("field")}
        self.assertIn("win.eventdata.user", fields_persist)
        self.assertIn("socrunner", fields_persist["win.eventdata.user"])

    # -------------------------------------------------------------------------
    # 7. Regex Pattern Compilation Checks
    # -------------------------------------------------------------------------
    def test_decoder_and_rule_regexes_compile(self):
        """All regex patterns in decoders and rules must compile without syntax errors."""
        # Decoder regexes
        for d_elem in self.decoder_root.findall(".//regex"):
            if d_elem.text:
                try:
                    re.compile(d_elem.text)
                except re.error as e:
                    self.fail(f"Invalid regex in decoder: '{d_elem.text}' -> {e}")

        # Rule field regexes (handling PCRE2 expressions)
        for f_elem in self.rules_root.findall(".//field"):
            if f_elem.text:
                try:
                    re.compile(f_elem.text)
                except re.error as e:
                    self.fail(f"Invalid regex in rule field: '{f_elem.text}' -> {e}")

    # -------------------------------------------------------------------------
    # 8. SOC Operational Directives: Single Integration Point & Zero Secrets
    # -------------------------------------------------------------------------
    def test_single_n8n_integration_block(self):
        """Must maintain exactly ONE <integration> block for custom-n8n in ossec.conf."""
        integrations = self.ossec_root.findall(".//integration")
        n8n_integrations = [
            i for i in integrations
            if i.findtext("name") == "custom-n8n"
        ]
        self.assertEqual(
            len(n8n_integrations), 1,
            f"Expected exactly 1 custom-n8n integration, found {len(n8n_integrations)}"
        )
        integ = n8n_integrations[0]
        hook_url = integ.findtext("hook_url")
        self.assertIsNotNone(hook_url)
        self.assertIn("/webhook/wazuh-alert", hook_url)

    def test_zero_secret_leakage_in_templates(self):
        """Ensures template files do not contain exposed real secrets or API tokens."""
        if not ENV_EXAMPLE.exists():
            self.skipTest(".env.example not found")

        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        # Ensure only placeholder tokens are used
        self.assertIn("your_virustotal_api_key_here", content)
        self.assertIn("your_abuseipdb_api_key_here", content)
        self.assertIn("your_telegram_bot_token_here", content)
        self.assertIn("your_jira_api_token_here", content)

        # Telegram token format: digits:alphanumeric (no live token should match)
        live_telegram_token = re.search(r"^\s*TELEGRAM_BOT_TOKEN\s*=\s*\d{8,10}:[A-Za-z0-9_-]{35}", content, re.MULTILINE)
        self.assertIsNone(live_telegram_token, "Live Telegram Bot Token detected in .env.example!")

        # 64-character hex key (VirusTotal / generic API key)
        live_vt_key = re.search(r"^\s*VIRUSTOTAL_API_KEY\s*=\s*[0-9a-fA-F]{64}\s*$", content, re.MULTILINE)
        self.assertIsNone(live_vt_key, "Live 64-char API key detected in .env.example!")

    # -------------------------------------------------------------------------
    # 9. OpenSearch Executive Dashboard Saved Objects Validation (Pillar 3)
    # -------------------------------------------------------------------------
    def test_executive_dashboard_ndjson_integrity(self):
        """Verifies that the OpenSearch Executive Dashboard Saved Objects file is valid and complete."""
        self.assertTrue(DASHBOARD_NDJSON.exists(), f"Dashboard ndjson file not found at {DASHBOARD_NDJSON}")
        lines = [line.strip() for line in DASHBOARD_NDJSON.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 7, "Dashboard ndjson must contain at least 7 saved objects")

        objects = []
        for line in lines:
            try:
                obj = json.loads(line)
                objects.append(obj)
            except Exception as e:
                self.fail(f"Invalid JSON line in ndjson: {e}")

        types = [o["type"] for o in objects]
        self.assertIn("dashboard", types, "Missing dashboard object in ndjson")
        self.assertIn("visualization", types, "Missing visualization objects in ndjson")
        self.assertIn("search", types, "Missing search object in ndjson")
        self.assertIn("index-pattern", types, "Missing index-pattern object in ndjson")

        dash = next(o for o in objects if o["type"] == "dashboard")
        self.assertEqual(dash["id"], "soc-lab-executive-overview")
        self.assertEqual(dash["attributes"]["title"], "SOC Lab - Executive Incident Overview")

        # Verify panels are present in dashboard
        panels = json.loads(dash["attributes"]["panelsJSON"])
        self.assertGreaterEqual(len(panels), 6, "Dashboard must contain at least 6 panel visualizations")

    # -------------------------------------------------------------------------
    # 10. Sigma Rules & SigWaz Compiler Tests (Pillar 2 - Phase 8)
    # -------------------------------------------------------------------------
    def test_sigma_rules_schema_and_validity(self):
        """Verifies that all Sigma YAML rules conform to schema and MITRE ATT&CK standards."""
        from scripts.sigma_compiler import SigmaToWazuhCompiler
        self.assertTrue(SIGMA_DIR.exists(), f"Sigma rules directory missing: {SIGMA_DIR}")
        compiler = SigmaToWazuhCompiler(SIGMA_DIR)
        self.assertGreaterEqual(len(compiler.rules), 6, "Expected at least 6 Sigma detection rules")
        self.assertTrue(compiler.validate_all(), "One or more Sigma rules failed schema validation")

    def test_sigma_compiler_drift_check(self):
        """Guarantees zero-drift: custom-rules/local_rules.xml must match 100% with Sigma SSOT."""
        from scripts.sigma_compiler import SigmaToWazuhCompiler
        compiler = SigmaToWazuhCompiler(SIGMA_DIR)
        compiled_xml = compiler.compile_to_xml()
        current_xml = RULES.read_text(encoding="utf-8")

        current_normalized = "\n".join([line.rstrip() for line in current_xml.strip().splitlines()])
        compiled_normalized = "\n".join([line.rstrip() for line in compiled_xml.strip().splitlines()])

        self.assertEqual(
            current_normalized, compiled_normalized,
            "Drift detected between Sigma rules (SSOT) and custom-rules/local_rules.xml! Run 'python scripts/sigma_compiler.py --compile'."
        )

    def test_sigma_compiler_coverage_all_killchain_stages(self):
        """Verifies that the compiled rules cover all attack stages and SOAR child suppressions."""
        from scripts.sigma_compiler import SigmaToWazuhCompiler
        compiler = SigmaToWazuhCompiler(SIGMA_DIR)
        compiled_xml = compiler.compile_to_xml()
        root = ET.fromstring(compiled_xml)
        rule_ids = {r.attrib["id"]: r for r in root.findall("rule")}

        expected_ids = [
            "100001",  # RDP Brute Force
            "100002",  # Web LFI
            "100003",  # Sysmon EID 1 Base Filter
            "100004",  # PowerShell Executed
            "100008",  # PowerShell SOAR Suppression
            "100007",  # UAC Bypass ms-settings
            "100009",  # UAC SOAR Suppression
            "100006",  # Persistence Run Key
            "100010",  # Persistence SOAR Suppression
            "100005",  # LSASS Memory Dump
            "100011",  # NIDS Nmap Scan
            "100012",  # NIDS Web LFI
            "100013",  # NIDS Vulnerability Scanner
            "100014",  # Deception Canary File Access
            "100015",  # Deception Honey Account Logon
            "100016",  # Deception Port Decoy Probe
        ]
        for eid in expected_ids:
            self.assertIn(eid, rule_ids, f"Compiled XML missing expected rule ID: {eid}")

        # Check suppression rules are level 0 and reference their respective parent rules
        self.assertEqual(rule_ids["100008"].attrib["level"], "0")
        self.assertEqual(rule_ids["100008"].findtext("if_sid"), "100004")

        self.assertEqual(rule_ids["100009"].attrib["level"], "0")
        self.assertEqual(rule_ids["100009"].findtext("if_sid"), "100007")

        self.assertEqual(rule_ids["100010"].attrib["level"], "0")
        self.assertEqual(rule_ids["100010"].findtext("if_sid"), "100006")

    # -------------------------------------------------------------------------
    # 11. Suricata NIDS & XDR Integration Tests (Phase 9)
    # -------------------------------------------------------------------------
    def test_suricata_localfile_configured(self):
        """Verifies that ossec.conf includes /var/log/suricata/eve.json in JSON format."""
        localfiles = self.ossec_root.findall(".//localfile")
        suricata_entries = [
            lf for lf in localfiles
            if lf.findtext("location") == "/var/log/suricata/eve.json"
        ]
        self.assertEqual(len(suricata_entries), 1, "Missing /var/log/suricata/eve.json in ossec.conf localfile")
        self.assertEqual(suricata_entries[0].findtext("log_format"), "json", "Suricata eve.json must be configured with 'json' log_format")

    def test_suricata_soar_rules_included(self):
        """Verifies that Suricata alert rule IDs (86602, 86603, 86604) are included in custom-n8n integration."""
        n8n_integ = next(
            (i for i in self.ossec_root.findall(".//integration") if i.findtext("name") == "custom-n8n"),
            None
        )
        self.assertIsNotNone(n8n_integ, "Missing custom-n8n integration block in ossec.conf")
        rule_ids_text = n8n_integ.findtext("rule_id")
        self.assertIsNotNone(rule_ids_text, "Missing rule_id list in custom-n8n integration")
        for sid in ("86602", "86603", "86604"):
            self.assertIn(sid, rule_ids_text, f"Suricata rule ID {sid} missing from custom-n8n integration")

    def test_suricata_signatures_integrity(self):
        """Verifies that deployment/suricata/local.rules exists and contains valid signatures."""
        self.assertTrue(SURICATA_RULES.exists(), f"Missing Suricata local.rules at {SURICATA_RULES}")
        content = SURICATA_RULES.read_text(encoding="utf-8")
        for sid in ("2000001", "2000002", "2000003", "2000004"):
            self.assertIn(f"sid:{sid}", content, f"Missing signature SID {sid} in local.rules")
            self.assertIn("metadata:mitre_attack_id", content, f"Missing MITRE ATT&CK metadata in SID {sid}")

    def test_suricata_yaml_config_integrity(self):
        """Verifies that deployment/suricata/suricata.yaml exists and contains valid capture & EVE output settings."""
        self.assertTrue(SURICATA_YAML.exists(), f"Missing suricata.yaml at {SURICATA_YAML}")
        content = SURICATA_YAML.read_text(encoding="utf-8")
        self.assertIn("interface: ens33", content, "Missing ens33 capture interface in suricata.yaml")
        self.assertIn("/var/log/suricata/eve.json", content, "Missing eve.json output path in suricata.yaml")

    # -------------------------------------------------------------------------
    # 12. Active Response Instant Containment Tests
    # -------------------------------------------------------------------------
    def test_active_response_kill_process_and_netsh_configured(self):
        """Verifies that ossec.conf includes netsh (100001, 100002) and kill-process (100004, 100005)."""
        commands = {c.findtext("name"): c for c in self.ossec_root.findall(".//command")}
        self.assertIn("kill-process", commands, "Missing 'kill-process' command in ossec.conf")
        self.assertEqual(commands["kill-process"].findtext("executable"), "kill-process.cmd")
        self.assertEqual(commands["kill-process"].findtext("timeout_allowed"), "no")

        self.assertIn("netsh", commands, "Missing 'netsh' command in ossec.conf")
        self.assertEqual(commands["netsh"].findtext("executable"), "netsh.exe")

        ar_blocks = self.ossec_root.findall(".//active-response")
        ar_commands = {ar.findtext("command"): ar for ar in ar_blocks}

        # Check netsh AR covers RDP (100001), Web LFI (100002) and Deception (100014, 100015, 100016)
        self.assertIn("netsh", ar_commands, "Missing active-response block for netsh")
        netsh_rules = ar_commands["netsh"].findtext("rules_id")
        self.assertIsNotNone(netsh_rules)
        for rid in ("100001", "100002", "100014", "100015", "100016"):
            self.assertIn(rid, netsh_rules, f"Rule {rid} missing from netsh AR configuration")

        # Check kill-process AR covers PowerShell (100004) and LSASS Dump (100005)
        self.assertIn("kill-process", ar_commands, "Missing active-response block for kill-process")
        kill_rules = ar_commands["kill-process"].findtext("rules_id")
        self.assertIsNotNone(kill_rules)
        self.assertIn("100004", kill_rules)
        self.assertIn("100005", kill_rules)

        # Check collect-evidence AR covers Deception rules (100014, 100015, 100016)
        self.assertIn("collect-evidence", commands, "Missing command definition for collect-evidence")
        self.assertIn("collect-evidence", ar_commands, "Missing active-response block for collect-evidence")
        evidence_rules = ar_commands["collect-evidence"].findtext("rules_id")
        self.assertIsNotNone(evidence_rules)
        for rid in ("100014", "100015", "100016"):
            self.assertIn(rid, evidence_rules, f"Rule {rid} missing from collect-evidence AR configuration")

    # -------------------------------------------------------------------------
    # 13. Deception Technology & Active Defense Tests
    # -------------------------------------------------------------------------
    def test_deception_rules_in_soar_integration(self):
        """Verifies that Deception rule IDs (100014, 100015, 100016) are dispatched to custom-n8n."""
        n8n_integ = next(
            (i for i in self.ossec_root.findall(".//integration") if i.findtext("name") == "custom-n8n"),
            None
        )
        self.assertIsNotNone(n8n_integ, "Missing custom-n8n integration block in ossec.conf")
        rule_ids_text = n8n_integ.findtext("rule_id")
        self.assertIsNotNone(rule_ids_text, "Missing rule_id list in custom-n8n integration")
        for rid in ("100014", "100015", "100016"):
            self.assertIn(rid, rule_ids_text, f"Deception rule {rid} missing from custom-n8n integration")


if __name__ == "__main__":
    unittest.main()

