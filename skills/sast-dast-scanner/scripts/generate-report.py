#!/usr/bin/env python3

"""
SAST/DAST Scanner - Report Generator

Converts JSON findings to structured markdown reports with:
- Executive summary with risk scoring
- Findings organized by severity
- OWASP Top 10 mapping
- CWE alignment
- Remediation guidance
"""

import json
import sys
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

# CWE-502: Schema validation for JSON input
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
MAX_FIELD_LENGTH = 10000

def validate_finding(finding: dict) -> bool:
    """Validate a finding dict against expected schema."""
    if not isinstance(finding, dict):
        return False
    severity = finding.get("severity", "").upper()
    if severity and severity not in VALID_SEVERITIES:
        return False
    # Validate string fields aren't excessively long
    for key in ("title", "description", "remediation", "file", "code_example"):
        val = finding.get(key, "")
        if isinstance(val, str) and len(val) > MAX_FIELD_LENGTH:
            return False
    # Validate CWE format if present
    cwe = finding.get("cwe", "")
    if cwe and not isinstance(cwe, str):
        return False
    return True

# OWASP Top 10 2021 Mapping
OWASP_MAPPING = {
    "CWE-89": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-798": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-338": "A02:2021 - Cryptographic Failures",
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-1021": "A01:2021 - Broken Access Control",
    "CWE-20": "A03:2021 - Injection",
    "CWE-1333": "A03:2021 - Injection",
    "CWE-367": "A04:2021 - Insecure Design",
    "CWE-1025": "A03:2021 - Injection",
    "CWE-1321": "A03:2021 - Injection",
    "CWE-522": "A02:2021 - Cryptographic Failures",
    "CWE-614": "A02:2021 - Cryptographic Failures",
    "CWE-1004": "A01:2021 - Broken Access Control",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-1341": "A01:2021 - Broken Access Control",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-489": "A04:2021 - Insecure Design",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-770": "A04:2021 - Insecure Design",
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "CWE-90": "A03:2021 - Injection",
    "CWE-91": "A03:2021 - Injection",
}

# LLM Top 10 Mapping (2025)
LLM_MAPPING = {
    "CWE-94": "LLM01:2025 - Prompt Injection",
    "CWE-400": "LLM02:2025 - Insecure Output Handling",
    "CWE-502": "LLM02:2025 - Insecure Output Handling",
    "CWE-400": "LLM04:2025 - Model Denial of Service",
    "CWE-798": "LLM06:2025 - Sensitive Information Disclosure",
}

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}

class SecurityReport:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.total_risk_score = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.info_count = 0

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to the report"""
        self.findings.append(finding)

        severity = finding.get("severity", "INFO").upper()
        if severity == "CRITICAL":
            self.critical_count += 1
            self.total_risk_score += SEVERITY_SCORES["CRITICAL"]
        elif severity == "HIGH":
            self.high_count += 1
            self.total_risk_score += SEVERITY_SCORES["HIGH"]
        elif severity == "MEDIUM":
            self.medium_count += 1
            self.total_risk_score += SEVERITY_SCORES["MEDIUM"]
        elif severity == "LOW":
            self.low_count += 1
            self.total_risk_score += SEVERITY_SCORES["LOW"]
        else:
            self.info_count += 1
            self.total_risk_score += SEVERITY_SCORES["INFO"]

    def get_owasp_category(self, cwe: str) -> str:
        """Map CWE to OWASP category"""
        return OWASP_MAPPING.get(cwe, "Unknown")

    def get_llm_category(self, cwe: str) -> str:
        """Map CWE to LLM Top 10"""
        return LLM_MAPPING.get(cwe, "")

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10)"""
        total_findings = (self.critical_count + self.high_count +
                         self.medium_count + self.low_count + self.info_count)
        if total_findings == 0:
            return 0.0

        # Scale score to 0-10
        score = self.total_risk_score / total_findings
        return min(score, 10.0)

    def generate_markdown(self) -> str:
        """Generate markdown report"""
        lines = []

        # Header
        lines.append("# Security Vulnerability Report")
        lines.append("")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")

        risk_score = self.calculate_risk_score()
        total_findings = (self.critical_count + self.high_count +
                         self.medium_count + self.low_count + self.info_count)

        if risk_score >= 8:
            risk_label = "CRITICAL"
        elif risk_score >= 6:
            risk_label = "HIGH"
        elif risk_score >= 4:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"
        lines.append(f"**Risk Score**: {risk_score:.1f}/10 ({risk_label})")
        lines.append("")

        lines.append(f"**Total Findings**: {total_findings}")
        lines.append(f"- **CRITICAL**: {self.critical_count}")
        lines.append(f"- **HIGH**: {self.high_count}")
        lines.append(f"- **MEDIUM**: {self.medium_count}")
        lines.append(f"- **LOW**: {self.low_count}")
        lines.append(f"- **INFO**: {self.info_count}")
        lines.append("")

        # Findings by Severity
        if self.findings:
            lines.append("## Findings by Severity")
            lines.append("")

            # Group by severity
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for severity in severity_order:
                severity_findings = [f for f in self.findings
                                    if f.get("severity", "INFO").upper() == severity]

                if severity_findings:
                    lines.append(f"### {severity} ({len(severity_findings)})")
                    lines.append("")

                    for finding in severity_findings:
                        lines.append(f"#### {finding.get('title', 'Untitled')}")
                        lines.append("")

                        cwe = finding.get("cwe", "CWE-000")
                        lines.append(f"**CWE**: {cwe}")

                        owasp = self.get_owasp_category(cwe)
                        if owasp:
                            lines.append(f"**OWASP**: {owasp}")

                        llm = self.get_llm_category(cwe)
                        if llm:
                            lines.append(f"**LLM Top 10**: {llm}")

                        if "file" in finding:
                            lines.append(f"**Location**: {finding['file']}")
                        if "lines" in finding:
                            lines.append(f"**Lines**: {finding['lines']}")

                        lines.append("")

                        if "description" in finding:
                            lines.append("**Description**:")
                            lines.append(finding["description"])
                            lines.append("")

                        if "remediation" in finding:
                            lines.append("**Remediation**:")
                            lines.append(finding["remediation"])
                            lines.append("")

                        if "code_example" in finding:
                            lines.append("**Example**:")
                            lines.append("```")
                            lines.append(finding["code_example"])
                            lines.append("```")
                            lines.append("")

                        lines.append("---")
                        lines.append("")

        # OWASP Top 10 Mapping
        lines.append("## OWASP Top 10 2021 Mapping")
        lines.append("")

        owasp_categories = {}
        for finding in self.findings:
            cwe = finding.get("cwe", "CWE-000")
            category = self.get_owasp_category(cwe)
            if category not in owasp_categories:
                owasp_categories[category] = 0
            owasp_categories[category] += 1

        for category in sorted(owasp_categories.keys()):
            count = owasp_categories[category]
            lines.append(f"- {category}: {count} finding(s)")
        lines.append("")

        # LLM Top 10 Mapping
        llm_categories = {}
        for finding in self.findings:
            cwe = finding.get("cwe", "CWE-000")
            category = self.get_llm_category(cwe)
            if category and category not in llm_categories:
                llm_categories[category] = 0
            if category:
                llm_categories[category] += 1

        if llm_categories:
            lines.append("## OWASP Top 10 for LLM Applications 2025 Mapping")
            lines.append("")
            for category in sorted(llm_categories.keys()):
                count = llm_categories[category]
                lines.append(f"- {category}: {count} finding(s)")
            lines.append("")

        # Remediation Priorities
        lines.append("## Remediation Priorities")
        lines.append("")
        lines.append("### Quick Wins (LOW effort, HIGH impact)")
        lines.append("- Address CRITICAL findings immediately")
        lines.append("- Update dependencies with known vulnerabilities")
        lines.append("- Enable missing security headers")
        lines.append("- Configure secure cookie flags")
        lines.append("")
        lines.append("### Medium-term (MEDIUM effort, HIGH impact)")
        lines.append("- Implement input validation and sanitization")
        lines.append("- Add rate limiting to sensitive endpoints")
        lines.append("- Migrate hardcoded secrets to environment variables")
        lines.append("- Implement proper authentication/authorization")
        lines.append("")
        lines.append("### Long-term (HIGH effort, ongoing)")
        lines.append("- Implement SAST tool in CI/CD pipeline")
        lines.append("- Establish secure SDLC practices")
        lines.append("- Regular security training for team")
        lines.append("- Implement threat modeling for new features")
        lines.append("")

        # Reference Links
        lines.append("## References")
        lines.append("")
        lines.append("- [OWASP Top 10 2021](https://owasp.org/Top10/)")
        lines.append("- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)")
        lines.append("- [CWE/CWSS](https://cwe.mitre.org/)")
        lines.append("- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)")
        lines.append("")

        return "\n".join(lines)

def main():
    """Read JSON from stdin and generate report"""

    try:
        # Read from stdin or file
        if len(sys.argv) > 1:
            with open(sys.argv[1], 'r') as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)

        report = SecurityReport()

        # Handle both single finding and array of findings
        findings = data if isinstance(data, list) else [data]

        # CWE-502: Validate each finding before processing
        for finding in findings:
            if not validate_finding(finding):
                print(f"Warning: Skipping invalid finding: {str(finding)[:100]}", file=sys.stderr)
                continue
            report.add_finding(finding)

        # Generate and output markdown
        markdown = report.generate_markdown()

        # CWE-755: Safe file write with directory creation and error handling
        output_file = sys.argv[2] if len(sys.argv) > 2 else "security-report.md"
        output_path = Path(output_file)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(markdown)
        except (PermissionError, OSError) as e:
            print(f"Error writing report to {output_file}: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"Report generated: {output_file}")

        # Also print to stdout
        print("\n" + "="*60)
        print(markdown)

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
