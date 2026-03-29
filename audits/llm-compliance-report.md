# LLM Compliance & Transparency Report
## sast-dast-scanner

**Report Date**: 2026-03-29
**Auditor**: LLM Governance & Compliance Team (Claude Sonnet 4.6)
**Project**: sast-dast-scanner (Claude-assisted development)
**Framework**: EU AI Act Art. 25 & 52, OWASP LLM Top 10 2025, NIST SP 800-218A, NIST AI RMF
**Audit Type**: POST-FIX Re-audit (Prior score: 64/100 DEVELOPING)

---

## Executive Summary

**Overall LLM Compliance Score**: 82/100
**Status**: GOOD (70-89)

Significant improvement from the prior audit (64/100 DEVELOPING). The deletion of the obfuscated `gen_skill.py`, SHA-pinning of CI actions, private vulnerability disclosure, and audit JSON gitignore collectively lifted 5 of the 8 dimensions.

### Before / After Delta Table

| Dimension | Before | After | Delta | Status |
|-----------|--------|-------|-------|--------|
| 1. System Transparency | 65 | 78 | +13 | GOOD |
| 2. Training Data Disclosure | 70 | 75 | +5 | GOOD |
| 3. Risk Classification | 72 | 85 | +13 | GOOD |
| 4. Supply Chain Security | 45 | 82 | +37 | GOOD |
| 5. Consent & Authorization | 80 | 82 | +2 | GOOD |
| 6. Sensitive Data Handling | 55 | 85 | +30 | GOOD |
| 7. Incident Response | 68 | 88 | +20 | GOOD |
| 8. Bias Assessment | 50 | 55 | +5 | DEVELOPING |
| **Overall** | **64** | **82** | **+18** | **GOOD** |

---

## Dimension Scores

### Dimension 1: System Transparency — 78/100 (GOOD)

**Assessment**:
- AI (Claude) involvement is disclosed in commit messages: all fix and audit commits include `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`.
- `audits/contribution-analysis.md` explicitly documents the human/AI split.
- The SKILL.md and audit reports carry clear provenance.
- Gap: No per-file attribution in source code comments (e.g., no `# Generated with Claude` markers in scan-secrets.sh or generate-report.py). README does not explicitly state that the security scanner itself was AI-assisted.

**Regulatory Mapping**:
- EU AI Act Art. 52 — Transparency: PARTIAL (commit-level disclosure, not file-level)
- NIST AI RMF MAP 1.1 — Context and limitations: PASS
- ISO 27001 A.8.9 — Configuration management: PASS

**Scoring rationale**: 78 — Disclosure exists and is systematic at the commit/audit level but lacks in-code attribution markers.

---

### Dimension 2: Training Data Disclosure — 75/100 (GOOD)

**Assessment**:
- Security framework sources are explicitly cited in multiple locations:
  - `skills/sast-dast-scanner/references/owasp-top10-web.md` — OWASP Top 10 2021
  - `skills/sast-dast-scanner/references/owasp-top10-llm.md` — OWASP LLM Top 10 2025
  - `skills/sast-dast-scanner/references/sast-patterns.md` — SAST patterns
  - `skills/sast-dast-scanner/references/dast-checklist.md` — DAST checklist
- `generate-report.py` references OWASP, CWE, and LLM frameworks inline in the OWASP_MAPPING and LLM_MAPPING dicts.
- Gap: No version/date stamps on the reference documents. NIST SP 800-53 version not cited in scripts. CWE database version not documented.

**Regulatory Mapping**:
- EU AI Act Art. 53 — Technical documentation: PARTIAL
- NIST AI RMF MEASURE 2.6 — Data provenance: PARTIAL

**Scoring rationale**: 75 — Major sources cited and structured; missing version specifics.

---

### Dimension 3: Risk Classification — 85/100 (GOOD)

**Assessment**:
- All SAST/DAST findings carry accurate CWE IDs validated against the CWE database.
- Severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO) align with industry convention.
- OWASP Top 10 2021 and LLM Top 10 2025 cross-mappings are present in `generate-report.py`.
- The prior duplicate CWE-400 key (CWE-694) has been fixed — LLM category mapping is now correct.
- Input validation for findings schema (`validate_finding()`) prevents malformed data from corrupting risk scores.
- Gap: No CVSS scores assigned to findings. No false-positive rate documentation.

**Regulatory Mapping**:
- EU AI Act Art. 25 — Obligations of GPAI model providers: PASS
- NIST SP 800-53 RA-3 — Risk Assessment: PASS
- OWASP LLM Top 10 2025 LLM09 — Misinformation: GOOD (classification is accurate)

**Scoring rationale**: 85 — Accurate, well-structured classification with CWE/OWASP/LLM mappings. CVSS scoring would push toward 90+.

---

### Dimension 4: Supply Chain Security — 82/100 (GOOD)

**Assessment**:
- SLSA Level 2 achieved (up from 0-1).
- All CI `uses:` directives SHA-pinned with version-tag comments.
- `flake8==7.1.1` pinned in `requirements-dev.txt`.
- Signed commits confirmed (GPG signing in commit history).
- Obfuscated `gen_skill.py` (the primary supply-chain risk) permanently deleted.
- Gap: No SBOM generated. Runtime tool versions undocumented. No Dependabot for Actions SHA rotation. SLSA L3 provenance attestation not yet in place.

**Regulatory Mapping**:
- NIST SP 800-218A — Secure Software Development: GOOD
- SLSA v1.0 L2: PASS
- EU AI Act Art. 25 — Risk management: PASS
- ISO 27001 A.15 — Supplier relationships: PARTIAL

**Scoring rationale**: 82 — Material improvement from CI hardening and gen_skill.py removal. SBOM gap keeps score below 90.

---

### Dimension 5: Consent & Authorization — 82/100 (GOOD)

**Assessment**:
- The tool is fully opt-in: invoked only via explicit command-line execution or `run-audit-suite.sh`.
- No autonomous background processes or scheduled execution.
- Destructive actions (e.g., `git push` in audit suite) are gated behind the `--push` flag and confirmation.
- The `--fix` flag in the audit suite script is also explicit.
- Gap: There is no user-facing warning before scan-secrets.sh begins searching the filesystem. A `--dry-run` or `--confirm` mode would improve authorization posture.

**Regulatory Mapping**:
- EU AI Act Art. 14 — Human oversight: PASS
- NIST AI RMF GOVERN 1.2 — Human oversight: PASS
- SOC 2 CC6.1 — Access controls: PASS

**Scoring rationale**: 82 — Strong explicit consent model. Minor gap: no pre-scan confirmation prompt.

---

### Dimension 6: Sensitive Data Handling — 85/100 (GOOD)

**Assessment**:
- `.gitignore` now excludes all scan output JSON files (`*-audit.json`, `*-report.json`, `npm-audit.json`, `pip-audit.json`, `cargo-audit.json`, `go-deps.json`) — CWE-312 resolved.
- `scan-secrets.sh` does not log full secret values — it reports match counts and shows 3-line samples (grep/rg output). Samples could contain actual secret values in a positive-match scenario.
- `generate-report.py` validates and truncates field lengths via `MAX_FIELD_LENGTH = 10000`.
- No PII collection. No network egress of findings.
- Gap: The 3-line sample output in `scan-secrets.sh` could print actual secret values to stdout/logs. A redaction step (masking with `***`) would eliminate this risk entirely.

**Regulatory Mapping**:
- GDPR Art. 5 — Data minimization: PASS (no PII collected)
- NIST SP 800-53 SC-28 — Protection of information at rest: PASS (JSON excluded from git)
- ISO 27001 A.8.11 — Data masking: PARTIAL (sample output not masked)
- SOC 2 CC6.7 — Data classification: PASS

**Scoring rationale**: 85 — Strong improvement via .gitignore fix. Sample output masking gap prevents 90+.

---

### Dimension 7: Incident Response — 88/100 (GOOD)

**Assessment**:
- `SECURITY.md` now uses GitHub's private advisory system — responsible disclosure pathway is complete.
- `set -euo pipefail` in both Bash scripts ensures errors surface immediately.
- `scan-secrets.sh` returns `$FINDINGS` as exit code — callers can detect and act on secrets found.
- `generate-report.py` uses `sys.exit(1)` for JSON errors, file write errors, and unexpected exceptions.
- Every finding in audit reports includes CWE, severity, location, description, and remediation guidance.
- The post-commit audit suite implements a fix-then-reaudit loop (post-commit-audit SKILL.md).
- Gap: No automated alerting or notification on CRITICAL findings (e.g., no Slack/email webhook).

**Regulatory Mapping**:
- NIST SP 800-53 IR-4 — Incident Handling: PASS
- ISO 27001 A.16 — Incident Management: PASS
- SOC 2 CC7.3 — Incident Response: PASS

**Scoring rationale**: 88 — Excellent error surfacing, clear remediation guidance, and working reaudit loop. Automated alerting would push to 90+.

---

### Dimension 8: Bias Assessment — 55/100 (DEVELOPING)

**Assessment**:
- The scanner supports 6 package ecosystems (npm, pip, cargo, go, maven, gradle) — good language diversity.
- Pattern-based secret detection covers major providers (AWS, GitHub, GitLab, Stripe, Twilio, SendGrid, Slack, Discord, MongoDB, PostgreSQL).
- SECURITY.md explicitly documents known limitations: false positives from pattern matching, incomplete coverage of logic-level flaws, no guarantee of complete coverage.
- Gap: No quantified false-positive or false-negative rates documented. No automated test suite against known-vulnerable code samples to measure detection accuracy. No statistical fairness analysis across language ecosystems.

**Regulatory Mapping**:
- EU AI Act Art. 10 — Data governance: PARTIAL
- NIST AI RMF MEASURE 2.11 — Fairness: PARTIAL
- OWASP LLM Top 10 2025 LLM09 — Misinformation: PARTIAL

**Scoring rationale**: 55 — Known-limitation disclosure is positive. No measurement of FP/FN rates or cross-ecosystem parity.

---

## Recommendations

1. **Add in-code AI attribution comments** (Transparency +10): Add `# AI-assisted generation — reviewed by Justice` to the top of each generated script. This brings Dimension 1 to 90+.

2. **Implement secret sample redaction** (Sensitive Data Handling +8): In `scan-secrets.sh`, pipe sample matches through a redaction filter that masks values after `=` or `:` with `***`. Prevents secrets from appearing in CI logs.

3. **Generate and publish an SBOM** (Supply Chain Security +8): Run `cyclonedx-bom` or `syft` as a CI step and attach the SBOM as a GitHub Actions artifact. Achieves SLSA L3 prerequisites.

4. **Build a test corpus for detection accuracy** (Bias Assessment +20): Create a `tests/fixtures/` directory with known-positive and known-negative secret/injection samples. Run scan-secrets.sh against them in CI and assert expected match counts. This provides measurable FP/FN rates.

5. **Version-stamp reference documents** (Training Data Disclosure +8): Add a `Last-Updated: YYYY-MM-DD` and `Source-Version: x.y` header to each file in `skills/sast-dast-scanner/references/`. Satisfies NIST AI RMF MEASURE 2.6 data provenance.

---

## Regulatory Roadmap

| Milestone | Action | Frameworks Addressed |
|-----------|--------|---------------------|
| Sprint 1 | Secret sample redaction in scan-secrets.sh | GDPR, ISO 27001 A.8.11, SOC 2 CC6.7 |
| Sprint 1 | In-code AI attribution comments | EU AI Act Art. 52, NIST AI RMF MAP 1.1 |
| Sprint 2 | SBOM generation (CycloneDX 1.4) | NIST SP 800-218A, SLSA L3 prerequisites, ISO 27001 A.15 |
| Sprint 2 | Test corpus with FP/FN measurement | EU AI Act Art. 10, NIST AI RMF MEASURE 2.11 |
| Sprint 3 | SLSA L3 provenance attestation (Sigstore) | SLSA v1.0 L3, EU AI Act Art. 25 |
| Sprint 3 | Reference document version stamps | EU AI Act Art. 53, NIST AI RMF MEASURE 2.6 |
| Sprint 4 | Dependabot for Actions SHA rotation | NIST SP 800-218A, CWE-829 preventive control |

---

## Next Audit Recommendation

**Recommended next audit date**: 2026-06-29 (3 months) or immediately after implementing Sprint 1/2 items above. Focus areas: Dimensions 1, 6, 8.

**Target score**: 90+/100 (EXCELLENT) achievable by completing Sprint 1 and Sprint 2 items.
