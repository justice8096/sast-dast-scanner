---
name: sast-dast-scanner
description: >
  This skill should be used when the user asks to perform a security scan,
  security audit, or vulnerability check on a codebase or application.
  This skill should be used when the user asks to find injection vulnerabilities,
  detect hardcoded secrets, check for cryptographic weaknesses, or assess
  OWASP Top 10 compliance. This skill should be used when the user asks to
  review HTTP security headers, cookie flags, CORS configuration, or TLS
  settings. This skill should be used when the user asks to audit code,
  check whether code is secure, test for XSS or SQL injection, pen test,
  run a security review, or generate a security report. This skill should
  be used when code under review handles user input, authentication,
  payments, credentials, or network requests.
---

# SAST/DAST Security Scanner

Perform comprehensive static (SAST) and dynamic (DAST) security analysis across
JavaScript/TypeScript, Python, Java, Go, and Rust codebases. Produce structured
Markdown reports grouped by severity with CWE references and actionable
remediation guidance.

## Quick-start

1. Run scripts/scan-secrets.sh to detect hardcoded credentials.
2. Run scripts/scan-dependencies.sh to audit third-party packages.
3. Pipe findings JSON to scripts/generate-report.py to produce a Markdown report.
4. Apply SAST pattern analysis (see below) to source files.
5. Apply the DAST checklist (references/dast-checklist.md) to running endpoints.

---

## SAST Analysis

### Injection Vulnerabilities

Detect the following injection patterns across all supported languages.
Map each finding to the relevant CWE and OWASP A03:2021 category.

| Pattern | CWE | Languages |
|---|---|---|
| String-concatenated SQL queries | CWE-89 | JS, Python, Java, Go |
| Shell command execution with user input | CWE-78 | JS, Python, Go |
| Unsafe DOM sink assignment (innerHTML and framework equivalents) | CWE-79 | JS/TS |
| Path building without normalization: readFile(baseDir + userPath) | CWE-22 | JS, Python, Java |
| Unsanitized LDAP filters or XML without DTD protection | CWE-90/91 | Java, Python |

For language-specific patterns and examples, see references/sast-patterns.md.

### Insecure Deserialization (CWE-502 / OWASP A08:2021)

Flag any use of:
- Python pickle.loads() on untrusted data
- Java ObjectInputStream without class validation
- Dynamic code execution functions applied to JSON strings
- Function() constructor with user-controlled input

### Secrets and Credential Exposure (CWE-798 / OWASP A02:2021)

Use scripts/scan-secrets.sh to detect:
- AWS Access Keys (AKIA followed by 16 alphanumeric chars)
- GitHub personal access tokens (ghp_ prefix, 36 chars)
- Private key PEM blocks in source files
- Database connection strings with embedded passwords
- Slack tokens, Stripe live keys, JWT secrets, OAuth client secrets
- SendGrid, Mailgun, and Twilio API keys

All patterns use bounded quantifiers to avoid ReDoS risk (CWE-1333).

### Cryptographic Weaknesses (CWE-327 / CWE-338 / OWASP A02:2021)

Flag:
- MD5 or SHA1 hashing applied to passwords
- DES, RC4, or other deprecated cipher usage
- Weak PRNG (Math.random, random.randint) used for security tokens
- Hardcoded cryptographic keys in source
- UUID v1 (time-based, predictable) used as session identifiers

### Input Validation (CWE-20 / OWASP A03:2021)

Flag:
- Missing bounds checks on array access
- Unvalidated redirect targets passed to Location headers
- JWT signature verification disabled at runtime
- Missing type assertions before use in typed languages

### ReDoS: Regular Expression Denial of Service (CWE-1333)

Flag patterns with catastrophic backtracking including nested quantifiers and
overlapping character classes. Recommend possessive quantifiers, atomic groups,
or a linear-time regex engine.

### Race Conditions: TOCTOU (CWE-367 / OWASP A04:2021)

Flag check-then-act sequences: existence checks followed by non-atomic file
operations, unchecked state transitions in concurrent handlers, and lock-free
shared-state mutations in goroutines or async event loops.

### Type Confusion and Prototype Pollution (CWE-1025 / CWE-1321)

Flag loose equality comparisons where type coercion is security-relevant,
Object.assign without key filtering, and recursive property assignment from
user-controlled JSON.

---

## Language-Specific Guidance

For the full pattern catalogue by language, refer to references/sast-patterns.md.

- JavaScript/TypeScript: dynamic code execution, require with dynamic paths,
  missing CSRF tokens, unsafe DOM sinks
- Python: the pickle module, shell invocation via the os module, subprocess with shell=True,
  string-formatted SQL, JWT signature bypass
- Java: string-concatenated SQL, Class.forName with user input,
  unsafe deserialization, hardcoded Properties passwords
- Go: sql.Query with string concatenation, exec.Command with unsanitized args,
  disabled TLS via InsecureSkipVerify
- Rust: unjustified unsafe blocks, panic on user input,
  buffer overflows at FFI boundaries

---

## DAST Analysis

Apply DAST checks to running services or HTTP responses.
The full checklist is in references/dast-checklist.md.

### HTTP Security Headers

| Header | Issue | CWE |
|---|---|---|
| Content-Security-Policy | Missing or permits unsafe inline scripts | CWE-693 |
| Strict-Transport-Security | Missing or max-age below 31536000 | CWE-522 |
| X-Frame-Options | Absent, enabling clickjacking | CWE-1021 |
| X-Content-Type-Options | Missing nosniff directive | CWE-693 |
| Referrer-Policy | Absent or overly permissive | CWE-201 |

### Cookie Security

Flag any session cookie lacking:
- HttpOnly flag: enables script-based theft (CWE-1004)
- Secure flag: transmits over plain HTTP (CWE-614)
- SameSite=Lax or Strict: CSRF exposure (CWE-352)

Flag SameSite=None without the Secure attribute.

### CORS and Open Redirects

Flag wildcard Access-Control-Allow-Origin combined with credentialed requests
(CWE-1341) and query parameters passed directly to Location headers without
allowlist validation (CWE-601).

### Information Disclosure

Flag Server or X-Powered-By headers revealing version strings (CWE-200),
stack traces in HTTP error responses (CWE-489), and debug mode reachable in
production environments.

### Authentication and Session Management

Flag sessions in URL query parameters (CWE-384), missing rate limiting on
login or password-reset endpoints (CWE-770), and predictable or non-expiring
session identifiers.

---

## Scripts

### scripts/scan-dependencies.sh

Auto-detects the project package manager and runs the appropriate audit tool.
Accepts a single path argument (defaults to the current directory).

Supported managers: npm audit, pip-audit / safety, cargo audit, go list piped
to nancy sleuth, mvn dependency-check:check, gradle dependencyCheckAnalyze.

JSON audit reports are written to the current directory for downstream
processing with generate-report.py.

### scripts/scan-secrets.sh

Uses grep (or ripgrep when available) to search for hardcoded credentials and
sensitive configuration patterns. Accepts a single path argument.

Excludes node_modules, .git, vendor, dist, and lock files. Prints up to three
sample matches per pattern and a remediation checklist on completion.

### scripts/generate-report.py

Reads a JSON array of findings from stdin or a file argument and writes a
structured Markdown report to disk (defaults to security-report.md).

Usage:
    cat findings.json | python3 skills/sast-dast-scanner/scripts/generate-report.py
    python3 skills/sast-dast-scanner/scripts/generate-report.py findings.json out.md

Each finding object must contain at minimum severity and title. Optional
fields: cwe, file, lines, description, remediation, code_example.

The report includes:
1. Executive summary with composite risk score (0-10)
2. Findings grouped by severity (CRITICAL to INFO)
3. OWASP Top 10 2021 and LLM Top 10 2025 category mapping
4. Prioritised remediation roadmap

---

## Report Output Format

Every finding in the generated report uses this structure:

    ## [SEVERITY]: [Title]
    CWE: CWE-XXX
    OWASP: AXXXX:YYYY - [Category]
    Location: path/to/file.ext
    Lines: NN-NN
    Description: concise explanation of the vulnerability.
    Remediation: step-by-step fix with before/after code examples.

Severity scale: CRITICAL (9-10), HIGH (7-8.9), MEDIUM (4-6.9), LOW (1-3.9), INFO (0-0.9).

---

## Reference Materials

| File | Purpose |
|---|---|
| references/owasp-top10-web.md | OWASP Top 10 2021 - Web application checklist |
| references/owasp-top10-llm.md | OWASP Top 10 for LLM Applications 2025 |
| references/sast-patterns.md | Language-specific vulnerability patterns |
| references/dast-checklist.md | Runtime / HTTP security testing procedures |

---

## Limitations

- Pattern matching produces false positives and false negatives; manual review
  is required for all findings.
- Complex inter-procedural data flows and business-logic vulnerabilities may
  not be detected.
- Absence of findings does not guarantee security.
- Complement with dedicated tools such as Semgrep, SonarQube, or Snyk for
  production pipelines.
- Dependency scanning requires the relevant package manager to be installed
  (npm, pip-audit, cargo, go, mvn, gradle).
