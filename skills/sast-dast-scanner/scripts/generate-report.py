#!/usr/bin/env python3

"""
SAST/DAST Scanner - Report Generator

Converts JSON findings to structured markdown reports with:
- Provenance Block (required per Skill Versioning and Addendum Framework)
- Executive summary with risk scoring
- Findings organized by severity
- OWASP Top 10 mapping
- CWE alignment
- Remediation guidance
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path

# CWE-502: Schema validation for JSON input
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
MAX_FIELD_LENGTH = 10000

# Hard-coded framework versions — single source of truth, bumped when the skill
# version bumps. Audits emitted by this version certify against THESE framework
# versions and no others. See CHANGELOG.md for what changes when bumping.
FRAMEWORK_VERSIONS = (
    "OWASP Top 10:2021, "
    "OWASP LLM Top 10 v1.1 (2024-10), "
    "CWE List 4.16 (2024-11), "
    "CWE Top 25 (2024 release)"
)
SOURCES_CURRENT_AS_OF_DEFAULT = "2026-05"
CHANGELOG_URL = "https://github.com/justice8096/sast-dast-scanner/blob/master/CHANGELOG.md"


def _git(args: list, cwd: Optional[str] = None) -> Optional[str]:
    """Run a git command and return stripped stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + args, cwd=cwd, capture_output=True, text=True,
            check=False, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _detect_skill_version() -> str:
    """Read version from .claude-plugin/plugin.json relative to this script."""
    script_dir = Path(__file__).resolve().parent
    for parent in [script_dir.parent.parent.parent, script_dir.parent.parent, script_dir.parent]:
        plugin_json = parent / ".claude-plugin" / "plugin.json"
        if plugin_json.exists():
            try:
                with open(plugin_json, encoding="utf-8") as f:
                    return json.load(f).get("version", "unknown")
            except (json.JSONDecodeError, OSError):
                continue
    return "unknown"


def _detect_skill_commit() -> str:
    script_dir = str(Path(__file__).resolve().parent)
    return _git(["rev-parse", "--short", "HEAD"], cwd=script_dir) or "unknown"


def _detect_target_repo(cwd: str) -> str:
    url = _git(["config", "--get", "remote.origin.url"], cwd=cwd)
    if url:
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name
    return Path(cwd).name


def _detect_target_commit(cwd: str) -> str:
    return _git(["rev-parse", "--short", "HEAD"], cwd=cwd) or "unknown"


def _detect_target_branch(cwd: str) -> str:
    return _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd) or "unknown"


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
# Values are lists to allow a single CWE to map to multiple LLM categories.
LLM_MAPPING: Dict[str, List[str]] = {
    "CWE-94": ["LLM01:2025 - Prompt Injection"],
    "CWE-400": [
        "LLM02:2025 - Insecure Output Handling",
        "LLM04:2025 - Model Denial of Service",
    ],
    "CWE-502": ["LLM02:2025 - Insecure Output Handling"],
    "CWE-798": ["LLM06:2025 - Sensitive Information Disclosure"],
}

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}


class SecurityReport:
    def __init__(
        self,
        skill_version: Optional[str] = None,
        skill_commit: Optional[str] = None,
        target_repo: Optional[str] = None,
        target_commit: Optional[str] = None,
        target_branch: Optional[str] = None,
        sources_current_as_of: Optional[str] = None,
    ):
        self.findings: List[Dict[str, Any]] = []
        self.total_risk_score = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.info_count = 0
        # Provenance Block fields — required per Skill Versioning Framework.
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.skill_version = skill_version or _detect_skill_version()
        self.skill_commit = skill_commit or _detect_skill_commit()
        cwd = os.getcwd()
        self.target_repo = target_repo or _detect_target_repo(cwd)
        self.target_commit = target_commit or _detect_target_commit(cwd)
        self.target_branch = target_branch or _detect_target_branch(cwd)
        self.sources_current_as_of = sources_current_as_of or SOURCES_CURRENT_AS_OF_DEFAULT

    def _provenance_block(self) -> str:
        """Required Provenance Block per Skill Versioning and Addendum Framework."""
        lines = ["## Provenance Block", ""]
        lines.append(f"- **Generated**: {self.timestamp}")
        lines.append(f"- **Generated by**: sast-dast-scanner v{self.skill_version} (`{self.skill_commit}`)")
        lines.append(
            f"- **Target project**: {self.target_repo} @ `{self.target_commit}` "
            f"on branch `{self.target_branch}`"
        )
        lines.append(
            f"- **Sources current as of**: {self.sources_current_as_of} "
            f"(except where individual findings note otherwise)"
        )
        lines.append(f"- **Framework versions**: {FRAMEWORK_VERSIONS}")
        lines.append(f"- **Skill changelog**: {CHANGELOG_URL}")
        return "\n".join(lines)

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

    def get_llm_categories(self, cwe: str) -> List[str]:
        """Map CWE to LLM Top 10 (may return multiple categories)"""
        return LLM_MAPPING.get(cwe, [])

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

        # Provenance Block — required per Skill Versioning and Addendum Framework.
        lines.append(self._provenance_block())
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

                        llm_entries = self.get_llm_categories(cwe)
                        for llm in llm_entries:
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
        llm_categories: Dict[str, int] = {}
        for finding in self.findings:
            cwe = finding.get("cwe", "CWE-000")
            for category in self.get_llm_categories(cwe):
                llm_categories[category] = llm_categories.get(category, 0) + 1

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
        lines.append(
            "- [OWASP Top 10 for LLM Applications 2025]"
            "(https://owasp.org/www-project-top-10-for-large-language-model-applications/)"
        )
        lines.append("- [CWE/CWSS](https://cwe.mitre.org/)")
        lines.append("- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)")
        lines.append("")

        return "\n".join(lines)


def main():
    """Read JSON from a findings file (or stdin) and generate a security report.

    Emits a Provenance Block at the top of every report per the Skill Versioning
    and Addendum Framework — required for legal-grade audit reproducibility.
    """
    parser = argparse.ArgumentParser(
        description="Generate SAST/DAST security report from findings JSON. "
        "Emits a Provenance Block at the top of every report per the Skill "
        "Versioning and Addendum Framework."
    )
    parser.add_argument(
        "findings_file", nargs="?",
        help="Path to findings JSON file (default: read from stdin)"
    )
    parser.add_argument(
        "output_file", nargs="?", default="security-report.md",
        help="Output markdown file (default: security-report.md)"
    )
    # Provenance Block overrides — optional, auto-detected from git/plugin.json.
    parser.add_argument("--skill-version", help="Override detected skill version")
    parser.add_argument("--skill-commit", help="Override detected skill commit")
    parser.add_argument("--target-repo", help="Target project repo name (default: cwd git remote/basename)")
    parser.add_argument("--target-commit", help="Target project commit (default: cwd git short HEAD)")
    parser.add_argument("--target-branch", help="Target project branch (default: cwd git current branch)")
    parser.add_argument(
        "--sources-current-as-of",
        help="Override sources-current-as-of (YYYY-MM); default: " + SOURCES_CURRENT_AS_OF_DEFAULT
    )

    args = parser.parse_args()

    try:
        # Read from file or stdin
        if args.findings_file:
            with open(args.findings_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)

        report = SecurityReport(
            skill_version=args.skill_version,
            skill_commit=args.skill_commit,
            target_repo=args.target_repo,
            target_commit=args.target_commit,
            target_branch=args.target_branch,
            sources_current_as_of=args.sources_current_as_of,
        )

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

        # CWE-755: Safe file write with directory creation and error handling.
        # Encoding forced to utf-8 — report content contains checkmarks, em-dashes,
        # and other non-ASCII; Python on Windows defaults to cp1252 and raises
        # UnicodeEncodeError without this.
        output_path = Path(args.output_file)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(markdown, encoding='utf-8', newline='\n')
        except (PermissionError, OSError) as e:
            print(f"Error writing report to {args.output_file}: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"Report generated: {args.output_file}")

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
