import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Repo root is 2 levels up from tests/unit/
ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "custom-rules" / "local_rules.xml"
DECODERS = ROOT / "custom-rules" / "local_decoder.xml"


def parse_fragment(path):
    return ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")


class DetectionConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules_root = ET.parse(RULES).getroot()
        cls.decoder_root = parse_fragment(DECODERS)
        cls.rules = {r.attrib["id"]: r for r in cls.rules_root.findall("rule")}
        cls.decoders = {d.attrib["name"]: d for d in cls.decoder_root.findall("decoder")}

    def test_rule_ids_are_unique(self):
        ids = [r.attrib["id"] for r in self.rules_root.findall("rule")]
        self.assertEqual(len(ids), len(set(ids)))

    def test_brute_force_rule(self):
        rule = self.rules["100001"]
        self.assertEqual(rule.attrib["level"], "12")
        self.assertEqual(rule.attrib["frequency"], "5")
        self.assertEqual(rule.attrib["timeframe"], "60")
        self.assertEqual(rule.findtext("if_matched_sid"), "60122")
        self.assertEqual(rule.findtext("mitre/id"), "T1110")

    def test_lfi_rule(self):
        rule = self.rules["100002"]
        self.assertEqual(rule.attrib["level"], "10")
        self.assertEqual(rule.findtext("if_sid"), "31100")
        self.assertEqual(rule.findtext("mitre/id"), "T1190")
        for indicator in ("win.ini", "boot.ini", "..%2f", "..%252f", "../"):
            self.assertIn(indicator, rule.findtext("match"))

    def test_lfi_decoder_extracts_url(self):
        decoder = self.decoders["web-access-lfi"]
        self.assertEqual(decoder.findtext("parent"), "web-accesslog")
        self.assertEqual(decoder.findtext("order"), "url")
        self.assertEqual(decoder.findtext("regex"), r"GET (\S+)\sHTTP")

    def test_killchain_rules_present_and_configured(self):
        # Stage 1: PowerShell
        rule_ps = self.rules["100004"]
        self.assertEqual(rule_ps.attrib["level"], "12")
        self.assertEqual(rule_ps.findtext("mitre/id"), "T1059.001")

        # Stage 2: UAC Bypass
        rule_uac = self.rules["100007"]
        self.assertEqual(rule_uac.attrib["level"], "12")
        self.assertEqual(rule_uac.findtext("mitre/id"), "T1548.002")

        # Stage 3: Persistence Run Key
        rule_run = self.rules["100006"]
        self.assertEqual(rule_run.attrib["level"], "10")
        self.assertEqual(rule_run.findtext("mitre/id"), "T1547.001")

        # Stage 4: LSASS Access
        rule_lsass = self.rules["100005"]
        self.assertEqual(rule_lsass.attrib["level"], "12")
        self.assertEqual(rule_lsass.findtext("mitre/id"), "T1003.001")


if __name__ == "__main__":
    unittest.main()
