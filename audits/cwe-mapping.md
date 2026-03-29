# CWE Mapping Report
## sast-dast-scanner

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite (Claude Sonnet 4.6)
**Source Findings**: SAST/DAST Scan + Supply Chain Audit (re-audit)
**Commit**: 47e25ac / 7068b69
**Audit Type**: POST-FIX Re-audit

---

## Summary

| Metric | Prior Audit | This Audit | Delta |
|--------|------------|------------|-------|
| Total unique CWEs | 14 | 11 | -3 |
| CWEs fully resolved | — | 8 | — |
| CWEs with residual findings | — | 3 | — |
| Compliance framework mappings | 112 | 88 | -24 (resolved findings removed) |

---

## CWE Inventory — Resolved (Fixed This Cycle)

### CWE-94: Improper Control of Generation of Code ('Code Injection')
**Prior Severity**: CRITICAL
**Resolution**: `gen_skill.py` deleted. The `base64.b64decode` + `exec` blob-decode pattern is gone.
**Status**: RESOLVED

### CWE-426: Untrusted Search Path
**Prior Severity**: CRITICAL
**Resolution**: Resolved as part of gen_skill.py deletion. No remaining `exec` on externally-controlled strings.
**Status**: RESOLVED

### CWE-755: Improper Handling of Exceptional Conditions
**Prior Severity**: CRITICAL
**Resolution**: Resolved as part of gen_skill.py deletion.
**Status**: RESOLVED

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Prior Severity**: HIGH
**Resolution**: `EXCLUDE_DIRS` and `EXCLUDE_FILES` in `scan-secrets.sh` converted to Bash arrays; expanded via `"${arr[@]}"` — word-splitting injection eliminated.
**Status**: RESOLVED

### CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
**Prior Severity**: HIGH
**Resolution**: `TARGET_DIR` canonicalized to absolute path before use; scan functions called inside subshells with absolute manifest paths.
**Status**: RESOLVED

### CWE-694: Use of Multiple Resources with Duplicate Identifier
**Prior Severity**: HIGH
**Resolution**: `LLM_MAPPING` refactored to `Dict[str, List[str]]`; duplicate CWE-400 key eliminated.
**Status**: RESOLVED

### CWE-829: Inclusion of Functionality from Untrusted Control Sphere
**Prior Severity**: HIGH
**Resolution**: All CI `uses:` directives SHA-pinned.
**Status**: RESOLVED

### CWE-1104: Use of Unmaintained Third-Party Components
**Prior Severity**: HIGH
**Resolution**: `flake8==7.1.1` pinned in `requirements-dev.txt`; CI installs from pinned file.
**Status**: RESOLVED

### CWE-312: Cleartext Storage of Sensitive Information
**Prior Severity**: MEDIUM
**Resolution**: `.gitignore` updated to exclude all scan output JSON files.
**Status**: RESOLVED

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Prior Severity**: MEDIUM
**Resolution**: `SECURITY.md` updated to use GitHub private advisory reporting link.
**Status**: RESOLVED

---

## CWE Inventory — Active (Residual)

### CWE-20: Improper Input Validation
**Severity**: MEDIUM
**Findings**:
1. `scan-secrets.sh` — `TARGET_DIR` traversal guard does not canonicalize symlinks (MEDIUM-01)
2. `scan-dependencies.sh` — fragile `grep` fallback for JSON parsing when `jq` absent (MEDIUM-02)

**Framework Mappings**:

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A04:2021 — Insecure Design |
| OWASP LLM Top 10 2025 | LLM02:2025 — Insecure Output Handling |
| NIST SP 800-53 | SI-10 (Information Input Validation) |
| EU AI Act Art. 25 | Risk management for AI-assisted tools |
| ISO 27001 | A.8.29 (Security testing in development) |
| SOC 2 | CC6.1 (Logical access controls) |
| MITRE ATT&CK | T1190 (Exploit Public-Facing Application) |
| MITRE ATLAS | AML.T0043 (Craft Adversarial Data) |

### CWE-345: Insufficient Verification of Data Authenticity
**Severity**: LOW
**Finding**: `scan-dependencies.sh` — no session-binding check before parsing scan output JSON files (LOW-01)

**Framework Mappings**:

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A08:2021 — Software and Data Integrity Failures |
| OWASP LLM Top 10 2025 | LLM02:2025 — Insecure Output Handling |
| NIST SP 800-53 | SI-7 (Software, Firmware, and Information Integrity) |
| EU AI Act Art. 25 | Risk management |
| ISO 27001 | A.8.20 (Networks security) |
| SOC 2 | CC6.7 (Data classification) |
| MITRE ATT&CK | T1565 (Data Manipulation) |
| MITRE ATLAS | AML.T0031 (Erode ML Model Integrity) |

### CWE-1104: Use of Unmaintained Third-Party Components (residual — runtime tools)
**Severity**: LOW/INFO
**Finding**: Runtime tools (npm, pip-audit, cargo, maven, gradle, ripgrep, jq) are OS-provided and not version-pinned. Acceptable for CLI tooling but documented as a known limitation.

**Framework Mappings**:

| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 2021 | A06:2021 — Vulnerable and Outdated Components |
| OWASP LLM Top 10 2025 | LLM05:2025 — Supply Chain Vulnerabilities |
| NIST SP 800-218A | PW.4 (Reuse existing, well-secured software) |
| EU AI Act Art. 25 | Risk management |
| ISO 27001 | A.15.2 (Monitoring and review of supplier services) |
| SOC 2 | CC9.2 (Vendor management) |
| MITRE ATT&CK | T1195 (Supply Chain Compromise) |
| MITRE ATLAS | AML.T0010 (ML Supply Chain Compromise) |

---

## Aggregate Compliance Matrix

### OWASP Top 10 2021

| Category | CWEs Mapped | Prior Findings | Current Findings | Status |
|----------|------------|----------------|-----------------|--------|
| A01: Broken Access Control | CWE-200 | 1 MEDIUM | 0 | PASS — FIXED |
| A02: Cryptographic Failures | CWE-798, CWE-522 | 0 | 0 | PASS |
| A03: Injection | CWE-78, CWE-94, CWE-426 | 4 (3C+1H) | 0 | PASS — FIXED |
| A04: Insecure Design | CWE-20, CWE-367, CWE-1104 | 2 HIGH | 2 MEDIUM | IMPROVED |
| A05: Security Misconfiguration | — | 0 | 0 | PASS |
| A06: Vulnerable Components | CWE-829, CWE-1104 | 2 HIGH | 0 (dev); LOW residual (runtime) | IMPROVED |
| A07: Auth Failures | — | 0 | 0 | PASS |
| A08: Software & Data Integrity | CWE-94, CWE-694, CWE-345 | 3 CRITICAL + 1 HIGH | 1 LOW residual | IMPROVED |
| A09: Logging & Monitoring | CWE-755 | 1 CRITICAL | 0 | PASS — FIXED |
| A10: SSRF | — | 0 | 0 | PASS |

### OWASP LLM Top 10 2025

| Category | CWEs Mapped | Status |
|----------|------------|--------|
| LLM01: Prompt Injection | CWE-94 | PASS — FIXED (gen_skill.py deleted) |
| LLM02: Insecure Output Handling | CWE-400, CWE-502, CWE-345 | PARTIAL — CWE-694 fix improves; CWE-345 residual LOW |
| LLM03: Training Data Poisoning | — | N/A |
| LLM04: Model Denial of Service | CWE-400 | PASS — CWE-694 fix ensures both categories mapped |
| LLM05: Supply Chain Vulnerabilities | CWE-829, CWE-1104 | IMPROVED — CI pinned; runtime tools residual LOW |
| LLM06: Sensitive Information Disclosure | CWE-312, CWE-200 | PASS — FIXED |
| LLM07: Insecure Plugin Design | — | N/A |
| LLM08: Excessive Agency | — | N/A |
| LLM09: Misinformation | CWE-20 | PARTIAL — input validation gaps remain (MEDIUM) |
| LLM10: Unbounded Consumption | — | N/A |

### NIST SP 800-53

| Control | Description | CWEs | Status |
|---------|-------------|------|--------|
| SA-15 | Development Process, Standards, Tools | CWE-829, CWE-1104 | PASS — FIXED |
| SI-10 | Information Input Validation | CWE-20 | PARTIAL |
| SI-7 | Software Integrity | CWE-345, CWE-94 | IMPROVED |
| RA-3 | Risk Assessment | CWE-94, CWE-694 | PASS — FIXED |
| SC-28 | Protection of Information at Rest | CWE-312 | PASS — FIXED |
| IR-4 | Incident Handling | CWE-200, CWE-755 | PASS — FIXED |

### EU AI Act (Art. 25)

| Obligation | Status | Notes |
|-----------|--------|-------|
| Risk management | IMPROVED | Major risks resolved; 2 MEDIUM residual |
| Technical documentation | PASS | SECURITY.md, SKILL.md, AUDIT docs present |
| Transparency | PASS | AI involvement disclosed in commit messages and audit reports |
| Incident response | PASS | SECURITY.md has responsible disclosure |

### ISO 27001

| Control | Status |
|---------|--------|
| A.8.29 Security testing | PASS — CI lint + audit workflow |
| A.15.2 Supplier monitoring | PARTIAL — runtime tools unversioned |
| A.16 Incident management | PASS — SECURITY.md updated |
| A.8.11 Data masking | PASS — .gitignore excludes scan JSON |

### SOC 2

| Criterion | Status |
|-----------|--------|
| CC6.1 Logical access | PASS |
| CC6.7 Data classification | IMPROVED — .gitignore updated |
| CC7.3 Incident response | PASS |
| CC9.2 Vendor management | PARTIAL — runtime tool versions undocumented |

### MITRE ATT&CK

| Technique | CWE | Status |
|-----------|-----|--------|
| T1195: Supply Chain Compromise | CWE-829, CWE-94 | MITIGATED — SHA pins + gen_skill.py deleted |
| T1190: Exploit Public App | CWE-20 | PARTIAL — residual input validation gaps |
| T1565: Data Manipulation | CWE-345 | LOW residual |

### MITRE ATLAS

| Technique | CWE | Status |
|-----------|-----|--------|
| AML.T0010: ML Supply Chain Compromise | CWE-829 | MITIGATED |
| AML.T0043: Craft Adversarial Data | CWE-20 | PARTIAL |
| AML.T0031: Erode Model Integrity | CWE-345 | LOW residual |

---

## Verdict

**PASS** — 8 of 11 previously mapped CWEs are fully resolved. Active CWE count reduced from 14 to 3, all at MEDIUM or below. Cross-framework compliance has improved materially across all 8 mapped frameworks.
