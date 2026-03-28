# OWASP Top 10 2021 - Web Application Security

Quick reference for identifying and mitigating the top web application vulnerabilities.

## A01:2021 – Broken Access Control

**Description**: Users can act outside their intended permissions.

**Common Weaknesses**:
- Missing access checks on sensitive functions
- Path traversal `/admin` accessible to users
- Privilege escalation via parameter tampering
- JWT manipulation or missing signature validation

**Detection**:
- Can users access other users' resources by modifying IDs?
- Are there role checks before sensitive operations?
- Is authorization checked on backend (not just frontend)?

**Remediation**:
```javascript
// VULNERABLE
app.get('/user/:id', (req, res) => {
  const user = getUserById(req.params.id); // No auth check!
  res.json(user);
});

// SECURE
app.get('/user/:id', authenticate, (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = getUserById(req.params.id);
  res.json(user);
});
```

## A02:2021 – Cryptographic Failures

**Description**: Sensitive data exposure due to weak or missing encryption.

**Common Weaknesses**:
- Storing passwords in plaintext or with weak hashing
- Transmitting sensitive data over unencrypted connections
- Using deprecated algorithms (MD5, SHA1, DES)
- Hardcoded cryptographic keys
- Weak random number generation for tokens

**Detection**:
```python
# VULNERABLE
password = hashlib.md5(password).hexdigest()  # MD5 is broken

# VULNERABLE
secret_key = "hardcoded_secret_2026"

# VULNERABLE
import random
token = str(random.randint(100000, 999999))
```

**Remediation**:
```python
# SECURE
from werkzeug.security import generate_password_hash, check_password_hash
hashed = generate_password_hash(password, method='pbkdf2:sha256')

# SECURE
import secrets
token = secrets.token_urlsafe(32)

# SECURE - Use environment variables
secret_key = os.environ.get('SECRET_KEY')
```

## A03:2021 – Injection

**Description**: Untrusted data interpreted as executable code or commands.

**Common Weaknesses**:
- SQL injection via string concatenation
- Command injection from user input
- XSS via direct HTML injection
- LDAP injection in directory queries
- Expression language injection in templates

**SQL Injection Detection**:
```javascript
// VULNERABLE
const query = `SELECT * FROM users WHERE email='${userEmail}'`;
db.query(query);

// VULNERABLE
db.query("SELECT * FROM users WHERE id=" + userId);

// SECURE
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

**Command Injection Detection**:
```python
# VULNERABLE
import os
filename = request.args.get('file')
os.system(f"cat {filename}")

# SECURE
import subprocess
result = subprocess.run(['cat', filename], capture_output=True)
```

**XSS Detection**:
```javascript
// VULNERABLE - React
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// VULNERABLE - jQuery
$('#container').html(userInput);

// SECURE - React (auto-escapes)
<div>{userComment}</div>

// SECURE - jQuery
$('#container').text(userInput);
```

## A04:2021 – Insecure Design

**Description**: Missing or ineffective security controls.

**Common Weaknesses**:
- Authentication not required for sensitive operations
- No rate limiting on login endpoints
- Missing CSRF protection on state-changing operations
- Debug mode enabled in production
- Predictable password reset tokens

**Detection**:
- Does login have rate limiting?
- Are there CSRF tokens on forms?
- Is sensitive data cached?
- Can users enumerate other resources?

**Remediation**:
```javascript
// Add rate limiting
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5 // 5 requests per 15 minutes
});
app.post('/login', loginLimiter, (req, res) => { ... });

// Use strong CSRF tokens
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });
```

## A05:2021 – Broken Authentication

**Description**: Authentication mechanisms are weak or bypassed.

**Common Weaknesses**:
- Weak password requirements
- Session IDs in URLs (logged in server/proxy logs)
- Sessions not invalidated on logout
- Credentials not sent over HTTPS
- Multi-factor authentication not enforced

**Detection**:
```javascript
// VULNERABLE - Session in URL
http://example.com/page?jsessionid=ABC123DEF456

// VULNERABLE - Weak password requirements
if (password.length < 4) { ... }

// SECURE - Session in secure cookie
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict'
});
```

## A06:2021 – Sensitive Data Exposure

**Description**: Sensitive data is exposed through various means.

**Common Weaknesses**:
- Passwords stored without hashing
- PII logged in error messages
- Backup files exposed (`.bak`, `.sql`)
- API responses contain unnecessary sensitive data
- Credentials in version control history

**Detection**:
- Are database credentials in environment files?
- Do logs contain passwords or tokens?
- Are backups protected?
- Does API return unnecessary user data?

**Remediation**:
```python
# VULNERABLE
print(f"User {username} failed login with password {password}")

# SECURE
print(f"User {username} failed login")

# VULNERABLE
user_data = { "id": 1, "email": "x@x.com", "password_hash": "..." }
return user_data

# SECURE
user_data = { "id": 1, "email": "x@x.com" }
return user_data
```

## A07:2021 – Identification and Authentication Failures

**Description**: Improper identity verification and session management.

**Common Weaknesses**:
- Predictable session tokens
- Account enumeration via registration/password reset
- Default credentials not changed
- Weak password reset mechanisms
- Concurrent sessions allowed indefinitely

**Detection**:
- Can you predict session IDs?
- Does registration reveal if email exists?
- Are there default accounts?
- Can you stay logged in indefinitely?

## A08:2021 – Software and Data Integrity Failures

**Description**: Assumptions about software updates and CI/CD pipelines are not verified.

**Common Weaknesses**:
- Insecure deserialization of untrusted data
- Unsigned/unencrypted deployment artifacts
- Dependencies without integrity checks
- Auto-update without signature verification

**Detection**:
```python
# VULNERABLE
import pickle
data = pickle.loads(untrusted_data)

# SECURE
import json
data = json.loads(untrusted_data)

# VULNERABLE - No integrity check
downloaded_file = requests.get(url)
exec(downloaded_file.content)

# SECURE - Verify signatures
verify_pgp_signature(downloaded_file)
```

## A09:2021 – Logging and Monitoring Failures

**Description**: Insufficient logging and alerting of security events.

**Common Weaknesses**:
- Failed login attempts not logged
- No alerting on suspicious patterns
- Logs not protected from tampering
- Logs sent over unencrypted channels
- No detection of unusual access patterns

**Remediation**:
```javascript
// Log security events
app.post('/login', (req, res) => {
  if (loginFailed) {
    logger.warn('Failed login attempt', {
      username: req.body.username,
      ip: req.ip,
      timestamp: new Date()
    });
  }
});

// Monitor for anomalies
if (failedLoginCount > 5 * 60 * 1000) {
  alertSecurityTeam('Brute force attempt detected');
}
```

## A10:2021 – Server-Side Request Forgery (SSRF)

**Description**: Application fetches remote resources without validating user input.

**Common Weaknesses**:
- No validation of URLs passed to HTTP client
- Access to internal services (169.254.169.254 for AWS metadata)
- XML/XXE allowing external entity expansion
- No DNS rebinding protection

**Detection**:
```python
# VULNERABLE
import requests
url = request.args.get('url')
response = requests.get(url)  # User can target internal APIs!

# VULNERABLE
# Can be exploited with: http://169.254.169.254/latest/meta-data/
```

**Remediation**:
```python
# SECURE
from urllib.parse import urlparse

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.hostname in ['169.254.169.254', 'localhost', '127.0.0.1']:
        raise ValueError('Internal URL not allowed')
    return requests.get(url, timeout=5)
```

## Quick Assessment Checklist

- [ ] Authentication enforced on all protected resources
- [ ] Passwords hashed with strong algorithm (bcrypt, Argon2)
- [ ] All data input validated and sanitized
- [ ] HTTPS enforced everywhere
- [ ] Security headers present (CSP, HSTS, X-Frame-Options)
- [ ] Session management robust (secure cookies, timeout)
- [ ] CSRF tokens on state-changing operations
- [ ] Rate limiting on sensitive endpoints
- [ ] Security logging and monitoring active
- [ ] Dependencies regularly updated
- [ ] No hardcoded credentials or secrets
- [ ] Error messages don't leak information
- [ ] Access controls enforced server-side
- [ ] Sensitive data encrypted at rest and in transit

---

**Reference**: https://owasp.org/Top10/
