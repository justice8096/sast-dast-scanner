<!-- SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to this skill are tracked here. Per the [Skill Versioning and Addendum Framework](https://github.com/justice8096/SecondBrainData/blob/main/SoftwarePractices/Skill-Versioning-and-Addendum-Framework.md), every change is classified by driver so downstream audit-artifact consumers can assess whether prior outputs need addendum filings.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with **change-driver tags** appended per entry:

- `[authority]` — underlying regulation, standard, or evidence base changed
- `[defect]` — typo, broken citation, misspelled term, wrong CFR number, factual error
- `[structural]` — section restructure, new locale, new lifespan layer, new domain, new severity scale
- `[voice]` — wording refinement, tone adjustment, ambiguity fix, accessibility improvement

All four drivers affect admissibility / persuasive weight of downstream artifacts. Every change is tracked equally.

## [Unreleased]

## [1.1.0] — 2026-05-17

Skill Versioning and Addendum Framework integration. Aligns sast-dast-scanner with the framework piloted in dyscalculia-support-skill v1.3.0–v1.3.2 and applied across six sibling skill repos (dyslexia v1.3.0, LLMComplianceSkill v1.2.0, ai-compliance-extractors v1.1.0, post-commit-audit v1.2.0, supply-chain-security v1.1.0).

This is a documentation/governance release — no behavior changes to SAST patterns, DAST checks, scripts, or report format.

### Added `[structural]`
- `CHANGELOG.md` (this file) adopting the four-driver classification with retroactive entries for v1.0.0 and v1.0.1.
- **Audit-Artifact Provenance Block** required at the top of every generated `sast-dast-scan.md` report. Captures skill version, commit hash, generation date, target-project repo + commit, sources-current-as-of, framework versions, CWE list date, changelog URL. Without it, prior audits can't be identified for addendum filings when CWE / OWASP frameworks update.

### Added `[authority]`
- Inline "*Sources current as of 2026-05*" markers + authority-version pin block in `skills/sast-dast-scanner/SKILL.md`. Pins:
  - OWASP Top 10:2021 (web application risks)
  - OWASP Top 10 for LLM Applications 2025 (published 2024-11)
  - CWE List 4.16 (2024-11) — the official CWE list at cwe.mitre.org; verify CWE numbers haven't been deprecated/renumbered before relying on a citation
  - CWE Top 25 (2024 release)
- Per-vulnerability section headers already cite specific CWE IDs (CWE-78, CWE-89, CWE-79, CWE-22, CWE-327, CWE-502, CWE-798, CWE-20, CWE-1333, CWE-367, CWE-1025, CWE-1321) and OWASP categories (A02:2021, A03:2021, A04:2021, A08:2021) — these stay current; only the umbrella framework versions are pinned in the new currency block.

### Process notes
- `.claude-plugin/plugin.json` version 1.0.1 → 1.1.0.
- License remains MIT (consistent across LICENSE file + plugin.json — no migration needed).

## [1.0.1] — 2026-03-29 (retroactively documented)

### Fixed `[defect]`
- Resolved SC2034 ShellCheck warnings (unused variable assignments) in the SAST/DAST scripts (commit `90d13d6`).

## [1.0.0] — 2026-03-29 (retroactively documented)

### Added `[structural]`
- Initial release of sast-dast-scanner skill. Five-language SAST coverage (JavaScript/TypeScript, Python, Java, Go, Rust) across 11 vulnerability classes: injection (CWE-78/89/79/22), insecure deserialization (CWE-502), secrets/credentials (CWE-798), cryptographic weaknesses (CWE-327/338), input validation (CWE-20), ReDoS (CWE-1333), TOCTOU race conditions (CWE-367), type confusion / prototype pollution (CWE-1025/1321). DAST runtime checks for HTTP security headers, cookie flags, CORS / open redirects, information disclosure, authentication/session management. Scripts: `scan-dependencies.sh`, `scan-secrets.sh`, `generate-report.py`.
- Self-audit artifacts in `audits/` (SAST/DAST scan of this skill, supply-chain audit, CWE mapping, LLM compliance report, contribution analysis, AUDIT_SUMMARY.txt).

---

## Change-driver workflow

When making a change:

1. **Classify the driver** — one of `[authority]`, `[defect]`, `[structural]`, `[voice]`.
2. **Cite the trigger** — for `[authority]`: name the CWE/OWASP version that changed. For `[defect]`: describe what was wrong. For `[structural]`/`[voice]`: explain why.
3. **Estimate addendum burden** — would any prior generated `sast-dast-scan.md` need addendum filings as a result of this change? If yes, flag it.

## Audit-artifact provenance

Every generated `sast-dast-scan.md` must begin with a provenance block of the form:

```
Generated YYYY-MM-DD by sast-dast-scanner vX.Y.Z (<skill-git-short-hash>)
Target project: <repo-name> @ <commit-short-hash> on branch <branch-name>
Sources current as of YYYY-MM except where individual findings note otherwise.
Framework versions: OWASP Top 10:2021, OWASP Top 10 for LLM Applications 2025 (2024-11),
                    CWE List 4.16 (2024-11), CWE Top 25 2024
Skill changelog: https://github.com/justice8096/sast-dast-scanner/blob/master/CHANGELOG.md
```

## Related framework documentation

- [Skill Versioning and Addendum Framework](https://github.com/justice8096/SecondBrainData/blob/main/SoftwarePractices/Skill-Versioning-and-Addendum-Framework.md) — the cross-skill engineering principle this CHANGELOG implements.
- [Master Task List entry 17](https://github.com/justice8096/SecondBrainData) — rollout: this is the 7th of 8 in-scope skills (cwe-mapper is the last remaining).
- [Orchestrator: post-commit-audit](https://github.com/justice8096/post-commit-audit) — calls this skill as one of three Phase-1 scanners.
- [Sister skills already on framework](https://github.com): [dyscalculia-support-skill](https://github.com/justice8096/dyscalculia-support-skill), [dyslexia-support-skill](https://github.com/justice8096/dyslexia-support-skill), [LLMComplianceSkill](https://github.com/justice8096/LLMComplianceSkill), [ai-compliance-extractors](https://github.com/justice8096/ai-compliance-extractors), [post-commit-audit](https://github.com/justice8096/post-commit-audit), [supply-chain-security](https://github.com/justice8096/supply-chain-security).
