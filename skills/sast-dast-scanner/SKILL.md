# SAST/DAST Security Scanner Skill

**Version**: 1.0.0
**Author**: Justice
**License**: MIT

## Overview

A comprehensive security vulnerability scanning skill that detects OWASP Top 10, CWE issues, and security misconfigurations through static analysis (SAST) and dynamic testing (DAST) without executing code.

## Trigger Conditions

Activate when Claude detects any of:

- "**security scan**" or "vulnerability check" or "security audit"
- "**is my code secure**" or "audit this code" or "code review"
- "**check for injection**" or "find security issues" or "security assessment"
- "**pen test**" or "security review" or "penetration test"
- "**OWASP**" or "CWE" or "CVE" or "security finding"
- Code handling **user input**, **authentication**, **payments**, or **network requests**
- Mention of **passwords**, **API keys**, **tokens**, **credentials** in code

## Capabilities

### SAST: Injection Vulnerabilities

**SQL Injection (CWE-89 / OWASP A03:2021)**
- String concatenation: `"SELECT * FROM users WHERE id=" + input`
- Template literals: `` `SELECT * FROM users WHERE id=${input}` ``
- Java string building: `String sql = "SELECT * FROM " + table;`

**Command Injection (CWE-78 / OWASP A03:2021)**
- Shell command execution: `exec('ls ' + userInput)`
- Runtime.exec() with tainted input
- Python subprocess without shell=False

**XSS: Cross-Site Scripting (CWE-79 / OWASP A03:2021)**
- Direct innerHTML assignment: `element.innerHTML = userInput`
- React dangerouslySetInnerHTML usage
- Vue v-html with unsanitized data
- Angular bypassSecurityTrustHtml()

**Path Traversal (CWE-22 / OWASP A01:2021)**
- `readFile(baseDir + userPath)` without normalization
- `open(request.getParameter("file"))`
- Missing path canonicalization

**LDAP/XML Injection (CWE-90/91)**
- Unsanitized LDAP filters
- XML parsing of untrusted data without DTD protection

### SAST: Insecure Deserialization

**Unsafe Serialization (CWE-502 / OWASP A08:2021)**
- Python pickle of untrusted data
- Java ObjectInputStream without validation
- Using eval() on JSON: `eval('(' + data + ')')`
- JavaScript Function constructor with user input

### SAST: Secrets & Credentials

**Hardcoded Secrets (CWE-798 / OWASP A02:2021)**
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- GitHub Tokens: `ghp_[a-zA-Z0-9]{36}`
- JWT Secrets: `secret: "hardcoded_value"`
- Database passwords: `password=root` in connection strings
- Private keys in code: `-----BEGIN PRIVATE KEY-----`
- Slack tokens: `xox[baprs]-[0-9a-zA-Z]{10,48}`

### SAST: Cryptographic Weaknesses

**Weak Algorithms (CWE-327 / OWASP A02:2021)**
- MD5, SHA1 for passwords: `hashlib.md5(password)`
- DES, RC4 encryption
- hardcoded cryptographic keys
- Weak random: `Math.random()` for tokens

**Insecure Randomness (CWE-338)**
- PRNG for security: `random.randint()`
- UUID v1 (predictable)
- Time-based seeds

### SAST: Input Validation

**Missing Validation (CWE-20 / OWASP A03:2021)**
- No bounds checking on arrays
- Missing type checking
- Unvalidated redirects: `return redirect(request.getParameter("url"))`
- Unvalidated regex matches

### SAST: ReDoS (Regular Expression DoS)

**Catastrophic Backtracking (CWE-1333)**
- `/^(a+)+$/` - nested quantifiers
- `/([a-zA-Z]+)*@gmail.com/` - overlapping patterns
- `/.*[!?]\w+/ /` - multiple wildcards

### SAST: Race Conditions

**TOCTOU (Time-of-Check-Time-of-Use) (CWE-367)**
- Check then act: `if (file.exists()) file.delete()`
- Unchecked state transitions in concurrent code
- Lock-free race windows

### SAST: Type Confusion & Prototype Pollution

**Type Coercion Issues (CWE-1025)**
- JavaScript `==` comparisons: `if (input == "admin")`
- Loose typing bypasses: `"0" == 0` returns true
- Object key poisoning in Node.js

**Prototype Pollution (CWE-1321)**
- Unsafe object merge: `Object.assign({}, proto, input)`
- Recursive property assignment from user data

## SAST: Language-Specific Patterns

### JavaScript/TypeScript
- Missing input sanitization in React
- Unsafe use of eval(), Function(), setTimeout(string)
- require() with dynamic paths: `require(userInput)`
- Missing CSRF tokens in forms

### Python
- Use of pickle with untrusted input
- os.system() or subprocess with shell=True
- SQL queries via string formatting
- JWT verification skipped: `jwt.decode(..., options={"verify_signature": False})`

### Java
- SQL queries via string concatenation
- unsafe reflection: `Class.forName(userInput)`
- insecure deserialization
- hardcoded passwords in Properties

### Go
- sql.Query with string concatenation
- exec.Command with unsanitized args
- disabled TLS verification

### Rust
- unsafe blocks without justification
- buffer overflows in FFI boundaries
- panics on user input

## DAST: HTTP Security Headers

**Content-Security-Policy (CWE-693)**
- Missing CSP or overly permissive: `script-src 'unsafe-inline'`
- unsafe-eval enabled for scripts

**Strict-Transport-Security (CWE-522)**
- Missing HSTS header
- Insufficient max-age (< 31536000)

**X-Frame-Options (CWE-1021)**
- Missing header (vulnerable to clickjacking)
- Allow-From usage (deprecated)

**X-Content-Type-Options (CWE-693)**
- Missing nosniff header allows MIME sniffing

**Referrer-Policy (CWE-201)**
- No or overly permissive referrer policy

## DAST: Cookie Security

**HttpOnly Flag (CWE-1004)**
- Session cookies without HttpOnly flag (XSS theft)

**Secure Flag (CWE-614)**
- Secure flag missing on HTTPS applications

**SameSite Flag (CWE-352)**
- Missing SameSite attribute (CSRF vulnerability)
- SameSite=None without Secure flag

## DAST: CORS & Open Redirects

**CORS Misconfiguration (CWE-1341)**
- `Access-Control-Allow-Origin: *` with credentials
- Wildcard origin with restricted headers

**Open Redirect (CWE-601)**
- Unvalidated redirects in auth flows
- Query parameter passed directly to Location header

## DAST: Information Disclosure

**Server Headers (CWE-200)**
- Server header revealing version information
- X-Powered-By header leaking framework
- Stack traces in error responses

**Debug Mode (CWE-489)**
- Debug flag enabled in production
- Verbose error messages exposing internals

## DAST: Authentication & Sessions

**Weak Session Management (CWE-384)**
- Sessions stored in URL query parameters
- Predictable session IDs
- Missing session timeout

**Missing Rate Limiting (CWE-770)**
- Brute force attack surface on login
- No throttling on API endpoints

## Report Generation

### Severity Scale

- **CRITICAL** (9.0-10.0): Immediate exploitable risk
- **HIGH** (7.0-8.9): Significant security impact
- **MEDIUM** (4.0-6.9): Moderate risk requiring mitigation
- **LOW** (1.0-3.9): Defense in depth improvement
- **INFO** (0-0.9): Informational security note

### Report Sections

1. **Executive Summary**: Risk score, critical count, top OWASP categories
2. **Findings by Severity**: Grouped with details, line numbers, fix guidance
3. **OWASP Mapping**: Cross-reference to Top 10 (2021) and LLM Top 10 (2025)
4. **CWE Alignment**: Common Weakness Enumeration IDs
5. **Remediation Priorities**: Quick wins and critical path fixes
6. **Metrics Dashboard**: Vulnerability distribution, coverage analysis

### Output Format

```markdown
## [SEVERITY]: [Title]

**CWE**: CWE-XXX
**OWASP**: AXXXX:YYYY - [Category]
**File**: path/to/file.js
**Lines**: 42-45

### Risk Score: X.X/10

### Description
Detailed explanation of vulnerability...

### Remediation
Step-by-step fix with code examples...

### References
- [OWASP A03:2021 - Injection](https://owasp.org/Top10/)
- [CWE-89: Improper Neutralization of Special Elements](...)
```

## Scripts

### scan-dependencies.sh
Auto-detects package manager and runs audits:
- npm: `npm audit`
- pip: `pip-audit`
- cargo: `cargo audit`
- go: `go list -json -m all | nancy sleuth`
- Maven: `mvn dependency-check:check`
- Gradle: depends plugin

### scan-secrets.sh
Grep/ripgrep pattern matching for:
- AWS keys, GitHub tokens, JWT secrets
- Database URLs with passwords
- Private keys, Slack/Discord tokens
- API keys (Stripe, SendGrid, etc.)

### generate-report.py
Stdin JSON to markdown report conversion:
- Groups findings by severity
- Calculates risk scores
- Maps CWE/OWASP categories
- Generates remediation summary

## Reference Materials

- **[OWASP Top 10 2021](./references/owasp-top10-web.md)** - Web vulnerabilities
- **[OWASP Top 10 for LLM Applications 2025](./references/owasp-top10-llm.md)** - LLM-specific risks
- **[SAST Patterns](./references/sast-patterns.md)** - Detailed patterns by language
- **[DAST Checklist](./references/dast-checklist.md)** - Runtime testing procedures

## Integration Examples

### With Claude Code
```
Claude, perform a security audit on this Express.js application. Check for OWASP Top 10 vulnerabilities and generate a detailed report.
```

### Command Line
```bash
claude-code run sast-dast-scanner \
  --path /app/src \
  --languages javascript,python \
  --severity high,critical \
  --output report.md
```

### CI/CD Pipeline
```yaml
security-scan:
  script:
    - ./scan-dependencies.sh .
    - ./scan-secrets.sh src/
    - Generate detailed report
  allow_failure: false
```

## Limitations

- Pattern matching may produce false positives/negatives
- Requires human review for all findings
- Complex logic flows may be missed
- No guarantee of complete coverage
- Use alongside Semgrep, SonarQube, Snyk for production scanning

## Version History

**v1.0.0** (2026-03-28)
- Initial release
- SAST patterns for 40+ vulnerability types
- DAST checks for HTTP security
- Multi-language support
- OWASP Top 10 mapping
- Structured report generation

---

**For questions or issues**: Open an issue on the project repository.
