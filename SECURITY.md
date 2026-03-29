# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in this project, please use GitHub's private
vulnerability reporting:
**[Report a vulnerability](https://github.com/justice8096/sast-dast-scanner/security/advisories/new)**

Do not open a public GitHub issue for security vulnerabilities, as this may
expose the vulnerability before a fix is available.

Do not publicly disclose a vulnerability before it has been assessed and a fix
or mitigation has been made available. Provide the following information in
your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions or components
- Any suggested remediation

Expect an initial response within 72 hours and a status update within 7 days.

---

## Scope

This project consists of:

- **Bash scripts** (`skills/sast-dast-scanner/scripts/scan-dependencies.sh`,
  `skills/sast-dast-scanner/scripts/scan-secrets.sh`) — shell-based tooling for
  dependency auditing and secret detection
- **Python script** (`skills/sast-dast-scanner/scripts/generate-report.py`) —
  JSON-to-Markdown report generator
- **Markdown reference files** (`skills/sast-dast-scanner/references/`) —
  static documentation; no executable code

**Out of scope:** There are no web components, servers, APIs, or user-facing
network services in this repository. Vulnerabilities in third-party tools
invoked by the scripts (npm, pip-audit, cargo, maven, gradle) should be
reported to those respective projects.

---

## Known Limitations

- **False positives and false negatives:** Pattern-based matching may flag
  benign code or miss obfuscated vulnerabilities. All findings require manual
  review by a qualified engineer.
- **No guarantee of complete coverage:** The scanner covers common patterns
  from OWASP Top 10 (2021) and CWE, but cannot detect every possible
  vulnerability class, especially novel or complex logic-level flaws.
- **Manual review required:** Results from this tool are advisory. Do not treat
  the absence of findings as a security certification.
- **Regex patterns:** Some secret-detection patterns may generate false positives
  on test fixtures, example files, or non-sensitive identifiers that happen to
  match the pattern shape.

---

## Dependencies

The scripts in this repository require the following runtime dependencies.
Keep these dependencies up to date to reduce supply-chain risk.

| Component | Minimum Version | Purpose |
|---|---|---|
| bash | 4.0+ | Runs `scan-dependencies.sh` and `scan-secrets.sh` |
| python3 | 3.6+ | Runs `generate-report.py` |
| npm (optional) | any | Node.js dependency scanning via `npm audit` |
| pip-audit or safety (optional) | any | Python dependency scanning |
| cargo + cargo-audit (optional) | any | Rust dependency scanning |
| maven (optional) | any | Java dependency scanning via `dependency-check:check` |
| gradle (optional) | any | Java/Kotlin dependency scanning |
| ripgrep (optional) | any | Faster secret pattern scanning (falls back to grep) |
| jq (optional) | any | Safe JSON parsing in summary output |

---

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x (current) | Yes |
| < 1.0.0 | No |
