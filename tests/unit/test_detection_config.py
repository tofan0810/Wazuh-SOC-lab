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


if __name__ == "__main__":
    unittest.main()
