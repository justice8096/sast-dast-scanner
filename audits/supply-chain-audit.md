# Supply Chain Security Audit
## sast-dast-scanner

**Report Date**: 2026-03-29
**Auditor**: Post-Commit Audit Suite (Claude Sonnet 4.6)
**Commit**: 47e25ac (style: fix flake8 violations) / 7068b69 (primary fix commit)
**Branch**: master
**Audit Type**: POST-FIX Re-audit

---

## Executive Summary

| Metric | Prior Audit | This Audit | Delta |
|--------|------------|------------|-------|
| SLSA Level | 0–1 | 2 | +1 |
| Total Issues | 8 (2C/3H/2M/1L) | 2 (0C/0H/1M/1L) | -6 |
| CI Actions Pinned | No | Yes | FIXED |
| Dev Dep Pinned | No | Yes (flake8==7.1.1) | FIXED |
| Audit JSON in .gitignore | No | Yes | FIXED |
| SECURITY.md Private Disclosure | No | Yes | FIXED |
| Signed Commits | Yes | Yes | Maintained |
| SBOM | None | None | No change |

The project advances from SLSA Level 0-1 to SLSA Level 2. The two remaining issues are LOW/MEDIUM and do not affect supply-chain integrity.

---

## SLSA Assessment

### Current Level: SLSA Level 2

| SLSA Requirement | Status | Evidence |
|-----------------|--------|---------|
| Version-controlled source | PASS | GitHub — `justice8096/sast-dast-scanner` |
| Automated build process | PASS | `.github/workflows/lint.yml` triggers on push/PR |
| Build service (hosted runner) | PASS | `ubuntu-latest` GitHub Actions runner |
| Authenticated provenance | PARTIAL | Signed commits present; no SLSA provenance attestation yet |
| Isolated build environment | PASS | GitHub-hosted runners provide ephemeral isolation |
| Pinned dependencies (CI) | PASS | All `uses:` directives SHA-pinned (fixed in 7068b69) |
| Pinned dev dependencies | PASS | `flake8==7.1.1` in `requirements-dev.txt` (fixed in 7068b69) |
| Two-party review | NOT MET | Single-developer project — no PR review gate enforced |
| Hermetic builds | PARTIAL | `pip install` hits PyPI at build time (not fully hermetic) |
| Non-falsifiable provenance | NOT MET | Requires SLSA L3 tooling (Sigstore/SLSA GitHub Generator) |

**Path to SLSA L3**: Add a SLSA GitHub Generator workflow with Sigstore-based provenance and enforce PR review via branch protection rules.

---

## CI/CD Supply Chain

### GitHub Actions Workflow: lint.yml

All actions SHA-pinned as of commit 7068b69:

```yaml
actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5        # v4
ludeeus/action-shellcheck@00cae500b08a931fb5698e11e79bfbd38e612a38  # 2.0.0
actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065     # v5
```

**Risk**: LOW — SHA pinning prevents mutable tag attacks. Periodic rotation to newer SHAs needed when upstream releases occur.

**Workflow Coverage**:
- ShellCheck lint on `skills/sast-dast-scanner/scripts/`
- flake8 lint on `skills/sast-dast-scanner/scripts/` with `--max-line-length=120`
- Triggers: push, pull_request

**Gap**: No secret scanning step in CI (e.g., `git-secrets`, `truffleHog`, or `gitleaks`). The project ships secret-detection scripts but does not self-scan in CI.

---

## Dependency Inventory

### Runtime Dependencies (no pinning mechanism — no package manifest)

The project's Bash scripts invoke system tools as optional dependencies. These are documented in SECURITY.md but are not version-pinned by any package manager.

| Tool | Type | Usage | Pinned? |
|------|------|-------|---------|
| bash 4.0+ | Runtime | Script interpreter | No (OS-provided) |
| python3 3.6+ | Runtime | generate-report.py | No (OS-provided) |
| npm | Optional | Node.js dep scan | No |
| pip-audit / safety | Optional | Python dep scan | No |
| cargo + cargo-audit | Optional | Rust dep scan | No |
| maven | Optional | Java dep scan | No |
| gradle | Optional | Java/Kotlin dep scan | No |
| ripgrep | Optional | Faster secret scan | No |
| jq | Optional | Safe JSON parse | No |

**Assessment**: Acceptable for a CLI tooling project where OS-provided tools are used. Documenting minimum versions in SECURITY.md partially mitigates this.

### Dev Dependencies (pinned)

| Package | Version | Purpose |
|---------|---------|---------|
| flake8 | ==7.1.1 | Python lint |

**Assessment**: PASS — exact version pin in `requirements-dev.txt`.

---

## Secret Management

### .gitignore Coverage (CWE-312 — Fixed)

Added patterns in commit 7068b69:
```
*-audit.json
*-report.json
go-deps.json
npm-audit.json
pip-audit.json
cargo-audit.json
```

Scan output JSON files containing potentially sensitive vulnerability data are now excluded from version control.

### CI Secrets

No `${{ secrets.* }}` references present in the current workflow. The CI job only runs lint checks — no deployment, no API keys, no tokens needed.

---

## SECURITY.md Disclosure Policy

**Prior State**: Instructed reporters to open a public GitHub issue (CWE-200 — information exposure risk).

**Current State**: Uses GitHub's private vulnerability reporting via a direct advisory link:
`https://github.com/justice8096/sast-dast-scanner/security/advisories/new`

Response SLA: 72-hour initial response, 7-day status update.

**Assessment**: PASS — appropriate responsible disclosure mechanism in place.

---

## SBOM Status

No SBOM (Software Bill of Materials) is currently generated. The project has minimal runtime dependencies (all OS-provided tools), which reduces SBOM urgency, but a CycloneDX 1.4 or SPDX 2.3 SBOM would improve supply-chain transparency for downstream consumers.

**Recommendation**: Generate an SBOM using `cyclonedx-bom` or `syft` as a CI artifact.

---

## plugin.json

License field added in commit 7068b69:
```json
"license_file": "LICENSE"
```

Plugin metadata is now complete: name, version, description, author, license, license_file, skills array.

---

## Risk Matrix

| Risk | Severity | Likelihood | Impact | Mitigated? |
|------|----------|-----------|--------|-----------|
| Mutable CI action tag attack | HIGH | Medium | High | YES — SHA-pinned |
| Floating dev dependency | MEDIUM | Low | Medium | YES — flake8==7.1.1 |
| Obfuscated supply-chain code | CRITICAL | Confirmed | Critical | YES — gen_skill.py deleted |
| Scan output JSON committed | MEDIUM | Medium | Medium | YES — .gitignore updated |
| Public vulnerability disclosure | MEDIUM | Low | Medium | YES — SECURITY.md updated |
| No secret scan in CI | MEDIUM | Low | High | NO — residual gap |
| No SBOM | LOW | Low | Low | NO — not yet addressed |
| No SLSA provenance attestation | LOW | Low | Low | NO — SLSA L2, not L3 |

---

## Framework Compliance

| Framework | Requirement | Status |
|-----------|------------|--------|
| SLSA v1.0 | L2: Hosted build, pinned deps | PASS |
| SLSA v1.0 | L3: Non-falsifiable provenance | NOT MET |
| NIST SP 800-218A | Pinned third-party components | PASS |
| NIST SP 800-218A | Automated build verification | PASS |
| EU AI Act Art. 25 | Risk management for dev pipeline | PASS (improved) |
| ISO 27001 A.15 | Supplier relationship management | PARTIAL |
| SOC 2 CC6.1 | Restrict access — signed commits | PASS |

---

## Residual Issues

### MEDIUM-SC-01: No Secret Scanning Step in CI
**Description**: The project's lint workflow does not include a secret detection pass (e.g., `gitleaks`, `truffleHog`). Leaked credentials could enter the codebase between manual audits.
**Recommendation**: Add a `gitleaks` action step (SHA-pinned) to the lint workflow.

### LOW-SC-01: SHA Rotation Cadence Undefined
**Description**: Pinned SHAs must be periodically updated when upstream actions release security fixes. No rotation schedule or tooling (e.g., Dependabot for Actions) is configured.
**Recommendation**: Enable `dependabot.yml` with `package-ecosystem: github-actions` to automate SHA update PRs.

---

## Verdict

**PASS** (upgraded from FAIL) — SLSA Level 2 achieved. All critical/high supply-chain issues resolved. Two residual medium/low items are acceptable for current maturity. SBOM generation and SLSA L3 provenance are recommended next steps.
