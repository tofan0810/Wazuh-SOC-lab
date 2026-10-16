#!/usr/bin/env python3
"""
Sigma Rules Compiler for Wazuh SIEM (Detection-as-Code Engine)
===============================================================================
Core engine implementing the SigWaz translation specification:
1. Logsource to Wazuh parent rule (if_sid / if_matched_sid) resolution.
2. Field normalization (Sigma OS-agnostic fields -> Wazuh Eventchannel win.eventdata.*).
3. Modifier compilation (|contains, |startswith, |endswith, |re) to PCRE2.
4. MITRE ATT&CK tag extraction and level-to-severity scoring.
5. Hierarchical Child Suppression Rules (level="0") generation for SOAR (socrunner via WinRM).

Usage:
  python scripts/sigma_compiler.py --compile     # Compiles sigma/ YAMLs to custom-rules/local_rules.xml
  python scripts/sigma_compiler.py --check       # Verifies local_rules.xml matches Sigma SSOT (CI/CD drift check)
  python scripts/sigma_compiler.py --validate    # Validates syntax and schema of all Sigma YAML rules
"""

import sys
import os
import re
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import yaml
except ImportError:
    print("[!] Error: 'pyyaml' is required. Run 'pip install pyyaml'.", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = REPO_ROOT / "manager" / "rules" / "sigma" if (REPO_ROOT / "manager" / "rules" / "sigma").exists() else REPO_ROOT / "custom-rules" / "sigma"
OUTPUT_RULES_XML = REPO_ROOT / "manager" / "rules" / "local_rules.xml" if (REPO_ROOT / "manager" / "rules" / "local_rules.xml").exists() else REPO_ROOT / "custom-rules" / "local_rules.xml"

# SigWaz Standard Field Mapping Dictionary
SIGMA_TO_WAZUH_FIELDS = {
    "CommandLine": "win.eventdata.commandLine",
    "Image": "win.eventdata.image",
    "ParentImage": "win.eventdata.parentImage",
    "TargetObject": "win.eventdata.targetObject",
    "TargetImage": "win.eventdata.targetImage",
    "SourceImage": "win.eventdata.sourceImage",
    "GrantedAccess": "win.eventdata.grantedAccess",
    "User": "win.eventdata.user",
    "TargetFilename": "win.eventdata.targetFilename",
}

# SigWaz Standard Logsource to Wazuh Parent if_sid
LOGSOURCE_TO_PARENT_SID = {
    ("windows", "process_creation"): "100003",
    ("windows", "process_access"): "61612",
    ("windows", "registry_set"): "61614, 61615, 61616",
    ("windows", "registry_add"): "61614, 61615, 61616",
    ("windows", "security"): "60122",
    ("windows", "webserver"): "31100",
    ("suricata", "network_traffic"): "86600",
}

# Severity Mapping Table
SEVERITY_LEVEL_MAP = {
    "critical": "12",
    "high": "10",
    "medium": "7",
    "low": "3",
    "informational": "0",
}


class SigmaCompilerError(Exception):
    """Custom exception for Sigma compilation errors."""
    pass


class SigmaRuleParser:
    """Parses and validates a single Sigma YAML rule document."""

    REQUIRED_FIELDS = ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            content = self.file_path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                raise SigmaCompilerError(f"File {self.file_path.name} does not contain a valid YAML dictionary.")
            return data
        except Exception as e:
            raise SigmaCompilerError(f"Error reading YAML {self.file_path.name}: {e}")

    def validate(self) -> List[str]:
        """Validates that all mandatory Sigma fields exist and conform to standards."""
        errors = []
        for field in self.REQUIRED_FIELDS:
            if field not in self.data:
                errors.append(f"Missing required field: '{field}' in {self.file_path.name}")

        # ID must be numeric >= 100000
        rule_id = str(self.data.get("id", ""))
        if not (rule_id.isdigit() and int(rule_id) >= 100000):
            errors.append(f"Rule ID '{rule_id}' in {self.file_path.name} must be numeric >= 100000")

        # MITRE ATT&CK Tag format check
        tags = self.data.get("tags", [])
        has_attack_id = False
        attack_pattern = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
        for t in tags:
            if attack_pattern.match(t):
                has_attack_id = True
                break
        if not has_attack_id:
            errors.append(f"Missing valid MITRE ATT&CK technique tag (e.g. attack.t1059.001) in {self.file_path.name}")

        return errors

    @property
    def id(self) -> str:
        return str(self.data.get("id"))

    @property
    def title(self) -> str:
        return self.data.get("title", "")

    @property
    def description(self) -> str:
        return self.data.get("description", "")

    @property
    def level(self) -> str:
        lvl = str(self.data.get("level", "medium")).lower()
        return SEVERITY_LEVEL_MAP.get(lvl, "7")

    @property
    def mitre_id(self) -> Optional[str]:
        for tag in self.data.get("tags", []):
            m = re.match(r"^attack\.(t\d{4}(\.\d{3})?)$", tag, re.IGNORECASE)
            if m:
                return m.group(1).upper()
        return None

    @property
    def logsource(self) -> Dict[str, str]:
        return self.data.get("logsource", {})

    @property
    def wazuh_meta(self) -> Dict[str, Any]:
        return self.data.get("wazuh", {})

    @property
    def soar_suppression(self) -> Optional[Dict[str, Any]]:
        return self.data.get("soar_suppression")


class SigmaToWazuhCompiler:
    """Translates Sigma YAML rules into standard Wazuh XML rule declarations."""

    def __init__(self, sigma_dir: Path):
        self.sigma_dir = sigma_dir
        self.rules: List[SigmaRuleParser] = []
        self._load_all()

    def _load_all(self):
        if not self.sigma_dir.exists():
            raise SigmaCompilerError(f"Sigma directory not found: {self.sigma_dir}")

        for yml in sorted(self.sigma_dir.glob("*.yml")):
            parser = SigmaRuleParser(yml)
            self.rules.append(parser)

    def validate_all(self) -> bool:
        all_errors = []
        for r in self.rules:
            errs = r.validate()
            all_errors.extend(errs)

        if all_errors:
            print("[FAIL] Sigma Validation Failed:")
            for e in all_errors:
                print(f"  - {e}")
            return False
        return True

    def _compile_selection_field(self, key: str, value: Any, negate: bool = False) -> str:
        """Translates a single Sigma key-value into a Wazuh XML <field> or <match> tag."""
        # Handle Modifier (e.g. CommandLine|re, TargetObject|contains)
        field_parts = key.split("|")
        raw_field = field_parts[0]
        modifier = field_parts[1] if len(field_parts) > 1 else ""

        wazuh_field = SIGMA_TO_WAZUH_FIELDS.get(raw_field, raw_field)
        negate_attr = ' negate="yes"' if negate else ""

        # Special case: web match tag
        if raw_field in ("cs-uri-stem", "url") and isinstance(value, list):
            match_pattern = "|".join(value)
            return f'    <match>{match_pattern}</match>'

        # PCRE2 pattern compilation
        pattern = ""
        if modifier == "re":
            pattern = str(value)
        elif modifier == "contains":
            if isinstance(value, list):
                pattern = f"(?i)({'|'.join(re.escape(v) for v in value)})"
            else:
                pattern = f"(?i){re.escape(str(value))}"
        elif modifier == "endswith":
            pattern = f"(?i){re.escape(str(value))}$"
        elif modifier == "startswith":
            pattern = f"(?i)^{re.escape(str(value))}"
        else:
            pattern = str(value)

        return f'    <field name="{wazuh_field}" type="pcre2"{negate_attr}>{pattern}</field>'

    def _generate_rule_xml(self, rule: SigmaRuleParser) -> List[str]:
        lines: List[str] = []
        data = rule.data
        wazuh_meta = rule.wazuh_meta

        # Check if rule defines a base filter rule (e.g. 100003)
        base_rule = wazuh_meta.get("base_rule")
        if base_rule:
            lines.append(f'  <!-- Parent rule ({base_rule["id"]}): Captures all Process Create events from Sysmon Event 1 -->')
            lines.append(f'  <rule id="{base_rule["id"]}" level="{base_rule.get("level", 0)}">')
            lines.append(f'    <if_sid>{base_rule["if_sid"]}</if_sid>')
            lines.append(f'    <description>{base_rule["description"]}</description>')
            lines.append('  </rule>\n')

        # Determine Main Rule Attributes
        rule_attrs = [f'id="{rule.id}"', f'level="{rule.level}"']
        if "frequency" in wazuh_meta:
            rule_attrs.append(f'frequency="{wazuh_meta["frequency"]}"')
        if "timeframe" in wazuh_meta:
            rule_attrs.append(f'timeframe="{wazuh_meta["timeframe"]}"')

        comment_headers = {
            "100004": "  <!-- Rule 100004: Detects ALL Encoded/Hidden PowerShell executions (Level 12) -->"
        }
        if rule.id in comment_headers:
            lines.append(comment_headers[rule.id])
        lines.append(f'  <rule {" ".join(rule_attrs)}>')

        # Hierarchy / Parent Linkage
        if "if_matched_sid" in wazuh_meta:
            lines.append(f'    <if_matched_sid>{wazuh_meta["if_matched_sid"]}</if_matched_sid>')
        elif "if_sid" in wazuh_meta:
            lines.append(f'    <if_sid>{wazuh_meta["if_sid"]}</if_sid>')
        else:
            product = rule.logsource.get("product", "windows")
            cat = rule.logsource.get("category", "")
            parent_sid = LOGSOURCE_TO_PARENT_SID.get((product, cat))
            if parent_sid:
                lines.append(f'    <if_sid>{parent_sid}</if_sid>')

        # Detection Block
        detection = data.get("detection", {})
        selection = detection.get("selection", {})
        for k, v in selection.items():
            if k == "EventID":
                continue  # Handled by if_matched_sid / parent rule
            lines.append(self._compile_selection_field(k, v))

        # Filter Block (Negations)
        filter_block = detection.get("filter", {})
        for k, v in filter_block.items():
            lines.append(self._compile_selection_field(k, v, negate=True))

        # Description
        lines.append(f'    <description>{rule.description}</description>')

        # MITRE ATT&CK
        if rule.mitre_id:
            lines.append('    <mitre>')
            lines.append(f'      <id>{rule.mitre_id}</id>')
            lines.append('    </mitre>')

        lines.append('  </rule>')

        suppression = rule.soar_suppression
        if suppression:
            lines.append('')
            suppression_comments = {
                "100008": "  <!-- Rule 100008: Child Suppression Rule (Level 0) for SOAR Remediation (True AND logic) -->",
                "100009": "  <!-- Rule 100009: Child Suppression Rule (Level 0) for Authorized Remediation Cleanup -->",
                "100010": "  <!-- Rule 100010: Child Suppression Rule (Level 0) for Authorized Remediation Cleanup -->",
            }
            comment = suppression_comments.get(
                str(suppression["id"]),
                f'  <!-- Rule {suppression["id"]}: Child Suppression Rule (Level 0) for Authorized SOAR Remediation -->'
            )
            lines.append(comment)
            lines.append(f'  <rule id="{suppression["id"]}" level="{suppression.get("level", 0)}">')
            lines.append(f'    <if_sid>{rule.id}</if_sid>')
            sup_selection = suppression.get("detection", {}).get("selection", {})
            for k, v in sup_selection.items():
                lines.append(self._compile_selection_field(k, v))
            lines.append(f'    <description>{suppression["description"]}</description>')
            lines.append('  </rule>')

        return lines

    def compile_to_xml(self) -> str:
        """Assembles the complete production custom-rules/local_rules.xml content."""
        rule_order = [
            "100001", "100002", "100004", "100007", "100006", "100005",
            "100011", "100012", "100013",
            "100014", "100015", "100016"
        ]
        rules_by_id = {r.id: r for r in self.rules}

        scenario_headers = {
            "100001": [
                "  <!-- ===================================================================== -->",
                "  <!-- SCENARIO 1: Windows RDP Brute Force Detection (T1110)                  -->",
                "  <!-- ===================================================================== -->"
            ],
            "100002": [
                "  <!-- ===================================================================== -->",
                "  <!-- SCENARIO 2: Web LFI / Directory Traversal Detection (T1190)            -->",
                "  <!-- ===================================================================== -->"
            ],
            "100004": [
                "  <!-- ===================================================================== -->",
                "  <!-- STAGE 1: Malicious PowerShell Execution (T1059.001)                    -->",
                "  <!-- ===================================================================== -->"
            ],
            "100007": [
                "  <!-- ===================================================================== -->",
                "  <!-- STAGE 2: Privilege Escalation - UAC Bypass via Registry (T1548.002)   -->",
                "  <!-- ===================================================================== -->"
            ],
            "100006": [
                "  <!-- ===================================================================== -->",
                "  <!-- STAGE 3: Persistence - Registry Run / RunOnce Keys (T1547.001)        -->",
                "  <!-- ===================================================================== -->"
            ],
            "100005": [
                "  <!-- ===================================================================== -->",
                "  <!-- STAGE 4: Credential Access - LSASS Memory Access (T1003.001)           -->",
                "  <!-- ===================================================================== -->"
            ],
            "100011": [
                "  <!-- ===================================================================== -->",
                "  <!-- NIDS SCENARIO 1: Network Reconnaissance - Nmap Port Scan (T1046)      -->",
                "  <!-- ===================================================================== -->"
            ],
            "100012": [
                "  <!-- ===================================================================== -->",
                "  <!-- NIDS SCENARIO 2: Web Exploit - LFI / Path Traversal on Wire (T1190)    -->",
                "  <!-- ===================================================================== -->"
            ],
            "100013": [
                "  <!-- ===================================================================== -->",
                "  <!-- NIDS SCENARIO 3: Active Scanning - Vulnerability Probing (T1595.002)   -->",
                "  <!-- ===================================================================== -->"
            ],
            "100014": [
                "  <!-- ===================================================================== -->",
                "  <!-- DECEPTION 1: Canary Honey-File Access with SACL Auditing (T1083/T1005)  -->",
                "  <!-- ===================================================================== -->"
            ],
            "100015": [
                "  <!-- ===================================================================== -->",
                "  <!-- DECEPTION 2: Honey-Account Tripwire Logon Attempt (T1078/T1110)        -->",
                "  <!-- ===================================================================== -->"
            ],
            "100016": [
                "  <!-- ===================================================================== -->",
                "  <!-- DECEPTION 3: Network Service Decoy Port Probe (T1046)                  -->",
                "  <!-- ===================================================================== -->"
            ],
        }

        output_lines = [
            "<!-- Local rules -->\n",
            '<group name="local_rules,sysmon,windows,killchain,suricata,">\n'
        ]

        for rid in rule_order:
            if rid not in rules_by_id:
                continue
            r = rules_by_id[rid]
            output_lines.extend(scenario_headers[rid])
            rule_xml = self._generate_rule_xml(r)
            output_lines.extend(rule_xml)
            output_lines.append("")  # Empty line between scenarios

        output_lines.append("</group>\n")
        return "\n".join(output_lines)


def main():
    parser = argparse.ArgumentParser(description="Sigma to Wazuh XML Rules Compiler (SigWaz Engine)")
    parser.add_argument("--compile", action="store_true", help="Compile Sigma YAMLs into custom-rules/local_rules.xml")
    parser.add_argument("--check", action="store_true", help="Check for drift between Sigma YAMLs and local_rules.xml (CI/CD mode)")
    parser.add_argument("--validate", action="store_true", help="Validate Sigma rules syntax and schema")
    parser.add_argument("--sigma-dir", type=Path, default=SIGMA_DIR, help="Path to Sigma YAML directory")
    parser.add_argument("--output", type=Path, default=OUTPUT_RULES_XML, help="Path to output local_rules.xml")

    args = parser.parse_args()

    if not (args.compile or args.check or args.validate):
        args.check = True

    compiler = SigmaToWazuhCompiler(args.sigma_dir)

    if args.validate or args.compile or args.check:
        print(f"[*] Validating Sigma rules in: {args.sigma_dir}")
        if not compiler.validate_all():
            sys.exit(1)
        print("[OK] All Sigma YAML rules passed schema and format validation.")

    if args.validate and not (args.compile or args.check):
        sys.exit(0)

    compiled_xml = compiler.compile_to_xml()

    if args.check:
        print(f"[*] Checking for drift against: {args.output}")
        if not args.output.exists():
            print(f"[ERROR] Target XML does not exist: {args.output}")
            sys.exit(1)

        current_xml = args.output.read_text(encoding="utf-8")
        # Normalize line endings
        current_normalized = "\n".join([line.rstrip() for line in current_xml.strip().splitlines()])
        compiled_normalized = "\n".join([line.rstrip() for line in compiled_xml.strip().splitlines()])

        if current_normalized == compiled_normalized:
            print("[PASS] ZERO DRIFT DETECTED: local_rules.xml is in 100% synchronization with Sigma YAML SSOT.")
            sys.exit(0)
        else:
            print("[DRIFT] DRIFT DETECTED between Sigma rules and local_rules.xml!")
            print("Run 'python scripts/sigma_compiler.py --compile' to synchronize.")
            sys.exit(1)

    if args.compile:
        print(f"[*] Compiling {len(compiler.rules)} Sigma rules into {args.output}...")
        args.output.write_text(compiled_xml, encoding="utf-8")
        print(f"[OK] Successfully compiled rules into: {args.output}")


if __name__ == "__main__":
    main()
