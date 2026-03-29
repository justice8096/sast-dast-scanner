# SAST/DAST Security Scan Report
## sast-dast-scanner

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite (Claude Sonnet 4.6)
**Commit**: 47e25ac — style: fix flake8 violations
**Prior Fix Commit**: 7068b69 — remove blob-decode gen_skill.py, harden scripts, SHA-pin CI, fix LLM_MAPPING duplicate key
**Branch**: master
**Audit Type**: POST-FIX Re-audit (verifying CRITICAL/HIGH resolution)

---

## Executive Summary

**Risk Score**: 1.5/10 (LOW)

| Severity | Prior Audit | This Audit | Delta |
|----------|-------------|------------|-------|
| CRITICAL | 3           | 0          | -3    |
| HIGH     | 5           | 0          | -5    |
| MEDIUM   | 4           | 2          | -2    |
| LOW      | 2           | 1          | -1    |
| INFO     | 3           | 1          | -2    |
| **Total**| **17**      | **4**      | **-13** |

All 3 CRITICAL and all 5 HIGH findings from the prior audit have been resolved. The project now presents a low overall risk posture. Two residual MEDIUM findings remain but neither blocks shipment.

---

## Resolved Findings (Previously CRITICAL / HIGH)

### RESOLVED — CRITICAL-01/02/03: Obfuscated Code Execution (gen_skill.py)
**CWE**: CWE-94 (Code Injection), CWE-426 (Untrusted Search Path), CWE-755 (Improper Exception Handling)
**Resolution**: `gen_skill.py` and `gen_skill_test.py` permanently deleted in commit 7068b69. The obfuscated blob-decode pattern (`base64.b64decode` + `exec`) that constituted all three CRITICAL findings has been eliminated. SKILL.md already existed as a replacement. No re-introduction risk.
**Status**: CLOSED

### RESOLVED — HIGH-01: Unpinned CI Actions (CWE-829)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Resolution**: All `uses:` directives in `.github/workflows/lint.yml` are now SHA-pinned with version-tag comments:
- `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4`
- `ludeeus/action-shellcheck@00cae500b08a931fb5698e11e79bfbd38e612a38  # 2.0.0`
- `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5`
**Status**: CLOSED

### RESOLVED — HIGH-02: Unpinned Dev Dependency / Missing requirements-dev.txt (CWE-1104)
**CWE**: CWE-1104 (Use of Unmaintained Third-Party Components)
**Resolution**: `requirements-dev.txt` added containing `flake8==7.1.1` (exact version pin). CI installs via `pip install -r requirements-dev.txt` rather than a floating `pip install flake8`.
**Status**: CLOSED

### RESOLVED — HIGH-03: EXCLUDE_DIRS as Unquoted String in grep (CWE-78)
**CWE**: CWE-78 (OS Command Injection via Improper Neutralization)
**Resolution**: `EXCLUDE_DIRS` and `EXCLUDE_FILES` in `scan-secrets.sh` converted from plain strings to Bash arrays; expanded via `"${EXCLUDE_DIRS[@]}"` and `"${EXCLUDE_FILES[@]}"` in all `grep`/`rg` invocations. Word-splitting-based injection path eliminated.
**Status**: CLOSED

### RESOLVED — HIGH-04: TOCTOU Race in scan-dependencies.sh (CWE-367)
**CWE**: CWE-367 (TOCTOU Race Condition)
**Resolution**: `TARGET_DIR` resolved to an absolute canonical path early in `main()` via `TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"`. Each `scan_*` call is wrapped in a subshell: `(cd "$TARGET_DIR" && scan_npm "$TARGET_DIR/package.json")`. Absolute manifest paths passed to all scan functions so relative-path drift cannot occur.
**Status**: CLOSED

### RESOLVED — HIGH-05: Duplicate CWE-400 Key in LLM_MAPPING (CWE-694)
**CWE**: CWE-694 (Use of Multiple Resources with Duplicate Identifier)
**Resolution**: `LLM_MAPPING` in `generate-report.py` refactored from `Dict[str, str]` to `Dict[str, List[str]]`. The duplicate `"CWE-400"` key now correctly maps to a list of two categories: `["LLM02:2025 - Insecure Output Handling", "LLM04:2025 - Model Denial of Service"]`. Method renamed `get_llm_category` -> `get_llm_categories`; all callers updated to iterate the list.
**Status**: CLOSED

---

## Remaining Findings

### MEDIUM-01: Incomplete Path Validation on TARGET_DIR (scan-secrets.sh)
**Severity**: MEDIUM
**CWE**: CWE-20 (Improper Input Validation)
**Location**: `skills/sast-dast-scanner/scripts/scan-secrets.sh` lines 12-16
**Description**: The traversal guard checks for `..` literal strings but does not canonicalize symlinks or validate that the resolved path is within a permitted root. An attacker supplying a path via a symlink chain could still reach unintended directories.
**Remediation**: Use `realpath --canonicalize-missing "$TARGET_DIR"` and verify the result starts with a permitted prefix, or restrict the tool to absolute paths only.
**Effort**: Low — 3-5 lines of additional guard code.

### MEDIUM-02: Fragile grep Fallback for JSON Parsing in scan-dependencies.sh
**Severity**: MEDIUM
**CWE**: CWE-20 (Improper Input Validation)
**Location**: `skills/sast-dast-scanner/scripts/scan-dependencies.sh` lines 237-238, 249-250
**Description**: When `jq` is not installed, the script falls back to `grep -o '"critical":[0-9]*'` to extract vulnerability counts from JSON. This pattern is brittle and silently fails on whitespace variations or nested keys. `jq` is already documented as an optional dependency in SECURITY.md.
**Remediation**: Promote `jq` to a soft-required dependency for the summary block with a clear warning on absence, or skip the parse and emit a human-readable note instead of attempting the fragile grep.
**Effort**: Low.

### LOW-01: Stale Scan Output JSON Could Mislead Summary
**Severity**: LOW
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Location**: `skills/sast-dast-scanner/scripts/scan-dependencies.sh` line 233
**Description**: The summary block checks `[[ -f "$TARGET_DIR/npm-audit.json" ]]` before parsing; it does not verify the file was produced by the current scan session. A file left over from a prior run could produce misleading output.
**Remediation**: Write scan output to a session-specific temp file and `mv` atomically, or include a session timestamp in the filename.
**Effort**: Low.

### INFO-01: Compiled Python Cache Present in Repository
**Severity**: INFO
**CWE**: N/A
**Location**: `skills/sast-dast-scanner/scripts/__pycache__/generate-report.cpython-312.pyc`
**Description**: A compiled Python bytecode file is tracked in the repository. The `.gitignore` already has `__pycache__/` but the directory was committed before the rule took effect.
**Remediation**: Run `git rm -r --cached skills/sast-dast-scanner/scripts/__pycache__/` to untrack without deleting the local file.
**Effort**: Minimal.

---

## Scan Coverage Summary

| Check Category | Covered | Notes |
|---------------|---------|-------|
| Hardcoded Secrets | Yes | scan-secrets.sh — 30+ patterns across AWS, GH, DB, JWT, Stripe, etc. |
| Dependency Vulnerabilities | Yes | scan-dependencies.sh — npm, pip, cargo, go, maven, gradle |
| OS Command Injection (CWE-78) | Yes | FIXED this cycle |
| TOCTOU Race (CWE-367) | Yes | FIXED this cycle |
| Obfuscated Code Execution (CWE-94) | Yes | FIXED this cycle — gen_skill.py deleted |
| Unpinned CI Actions (CWE-829) | Yes | FIXED this cycle |
| Unpinned Dev Deps (CWE-1104) | Yes | FIXED this cycle |
| Duplicate Data Keys (CWE-694) | Yes | FIXED this cycle |
| Input Validation (CWE-20) | Partial | Two residual MEDIUM findings |
| Path Traversal (CWE-22) | Partial | Basic guard present; see MEDIUM-01 |
| SQL Injection / XSS / CSRF | N/A | No database or web layer in project |
| ReDoS (CWE-1333) | Yes | Bounded quantifiers confirmed in scan-secrets.sh |

---

## OWASP Top 10 2021 Status

| Category | Prior Findings | Current Findings | Status |
|----------|---------------|-----------------|--------|
| A01: Broken Access Control | 0 | 0 | PASS |
| A02: Cryptographic Failures | 0 | 0 | PASS |
| A03: Injection | 4 | 0 | PASS — FIXED |
| A04: Insecure Design | 2 | 2 MEDIUM (residual) | CONDITIONAL PASS |
| A05: Security Misconfiguration | 0 | 0 | PASS |
| A06: Vulnerable Components | 1 HIGH | 0 | PASS — FIXED |
| A07: Auth Failures | 0 | 0 | PASS |
| A08: Software & Data Integrity | 3 CRITICAL | 0 | PASS — FIXED |
| A09: Logging & Monitoring Failures | 0 | 0 | PASS |
| A10: SSRF | 0 | 0 | PASS |

---

## Verdict

**PASS** — All CRITICAL and HIGH findings resolved. 2 MEDIUM + 1 LOW + 1 INFO remain; none block production release. Address in next sprint.

---

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE/CWSS](https://cwe.mitre.org/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
