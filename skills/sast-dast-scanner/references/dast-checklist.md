# DAST (Dynamic Application Security Testing) Checklist

Procedures for testing running applications for security issues.

## HTTP Security Headers

### Content-Security-Policy (CSP)
**Purpose**: Prevent XSS by controlling which resources can load

**Check**:
```bash
curl -I https://example.com | grep -i "content-security-policy"
```

**Good Policy**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' trusted.cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'
```

**Bad Policy**:
```
Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'
```

### Strict-Transport-Security (HSTS)
**Purpose**: Force HTTPS, prevent downgrade attacks

**Check**:
```bash
curl -I https://example.com | grep -i "strict-transport-security"
```

**Requirement**:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- max-age must be >= 31536000 (1 year)
- includeSubDomains should be present
- preload allows HSTS preload list inclusion

### X-Frame-Options
**Purpose**: Prevent clickjacking attacks

**Check**:
```bash
curl -I https://example.com | grep -i "x-frame-options"
```

**Options**:
- DENY: Page cannot be framed
- SAMEORIGIN: Only same origin can frame
- ALLOW-FROM uri: (Deprecated) Specific origin

**Requirement**: DENY or SAMEORIGIN

### X-Content-Type-Options
**Purpose**: Prevent MIME sniffing

**Check**:
```bash
curl -I https://example.com | grep -i "x-content-type-options"
```

**Requirement**: `X-Content-Type-Options: nosniff`

### Referrer-Policy
**Purpose**: Control how much referrer information is shared

**Check**:
```bash
curl -I https://example.com | grep -i "referrer-policy"
```

**Recommended**: `Referrer-Policy: strict-origin-when-cross-origin`

### Permissions-Policy
**Purpose**: Control which browser features/APIs can be used

**Check**:
```bash
curl -I https://example.com | grep -i "permissions-policy"
```

**Example**:
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Cookie Security

### HttpOnly Flag
**Purpose**: Prevent JavaScript from accessing cookies (XSS protection)

**Check**:
```bash
curl -I https://example.com 2>&1 | grep -i "set-cookie"
# Look for "HttpOnly" in response

# Or test in browser console:
document.cookie  # Shouldn't see session cookies
```

**Test**:
```javascript
// This should fail for HttpOnly cookies
console.log(document.cookie);
```

### Secure Flag
**Purpose**: Only send cookie over HTTPS

**Check**:
```bash
curl -I https://example.com 2>&1 | grep -i "set-cookie"
# Look for "Secure" in response
```

### SameSite Flag
**Purpose**: Prevent CSRF attacks

**Check**:
```bash
curl -I https://example.com 2>&1 | grep -i "set-cookie"
# Look for "SameSite" in response
```

**Values**:
- Strict: Cookies only sent with same-site requests
- Lax: Cookies sent with safe HTTP methods
- None: Cookies sent everywhere (requires Secure flag)

**Good Cookie**:
```
Set-Cookie: sessionId=abc123; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Strict
```

## CORS Testing

### Check CORS Headers
**Purpose**: Verify correct cross-origin request handling

```bash
# Test with origin header
curl -H "Origin: http://attacker.com" \
     -H "Access-Control-Request-Method: GET" \
     https://example.com

# Look for Access-Control-Allow-Origin response
```

### Vulnerabilities

**Bad: Allow all origins**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
CRITICAL: Credentials with wildcard origin!

**Bad: Dynamic origin without validation**
```
Access-Control-Allow-Origin: <echo of request origin>
```
Can be exploited with attacker-controlled origin

**Good**:
```
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
```

## Open Redirect Detection

### Test Cases
```bash
# Test 1: Query parameter redirect
https://example.com/login?redirect=https://attacker.com

# Test 2: Fragment redirect
https://example.com/login#https://attacker.com

# Test 3: Protocol-relative redirect
https://example.com/login?url=//attacker.com

# Test 4: Data URL redirect
https://example.com/login?url=data:text/html,<script>alert(1)</script>
```

### Remediation
```javascript
// VULNERABLE
function redirect(url) {
    window.location = url;
}

// SECURE - Validate destination
function redirect(url) {
    if (!isValidRedirectUrl(url)) {
        url = '/';
    }
    window.location = url;
}

function isValidRedirectUrl(url) {
    // Parse URL
    const parsed = new URL(url, window.location.origin);

    // Only allow same origin
    if (parsed.origin !== window.location.origin) {
        return false;
    }

    // Disallow dangerous protocols
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        return false;
    }

    return true;
}
```

## Information Disclosure

### Server Headers
```bash
curl -I https://example.com
```

**Problems**:
- Server header reveals version: `Server: Apache/2.4.41`
- X-Powered-By reveals framework: `X-Powered-By: Express`
- Version info in headers enables targeted attacks

**Fix**: Remove or obfuscate version info

### Stack Traces
**Test**:
```bash
# Trigger an error (if error handling is bad)
curl https://example.com/api/users/invalid
```

**Problems**:
- Stack traces expose source code paths
- File paths reveal server architecture
- Internal function names aid attack planning

**Fix**: Catch errors, log securely, return generic message

### Debug Mode
**Signs**:
- Verbose error messages
- Stack traces in responses
- Debug endpoints left enabled
- Source maps in production
- React/Vue DevTools showing state

```bash
# Check for source maps
curl https://example.com/bundle.js.map

# Check for debug endpoints
curl https://example.com/__debug__
curl https://example.com/.well-known/debug
```

### Directory Listing
```bash
curl https://example.com/uploads/
curl https://example.com/api/
```

**Problem**: Directory listing reveals file structure

**Fix**: Disable directory listing in web server config

## Authentication & Session Testing

### Session ID Quality
**Test**:
```bash
# Get multiple session IDs
for i in {1..10}; do
  curl -c session$i.txt https://example.com
  grep SESSIONID session$i.txt
done

# Analyze for patterns (should be random)
```

**Problems**:
- Predictable IDs (sequential: 1, 2, 3...)
- IDs based on timestamp
- Insufficient entropy

### Session Timeout
**Test**:
```bash
# Get session cookie
curl -c cookie.txt https://example.com/login -d "user=admin&pass=pass"

# Wait and test if session still valid
sleep 3600  # 1 hour
curl -b cookie.txt https://example.com/profile
```

**Problem**: No timeout allows indefinite session reuse

### Session Fixation
**Test**:
```bash
# Provide session ID in URL
https://example.com/login?sessionid=abc123

# After login, check if same ID is used
```

**Problem**: Attacker can predetermine session ID

### Authentication Bypass
**Tests**:
```bash
# Missing auth checks
curl https://example.com/admin  # Should require auth

# Weak password requirements
curl https://example.com/register -d "password=1"

# No account lockout
for i in {1..100}; do
  curl -d "user=admin&pass=wrong" https://example.com/login
done
```

## Rate Limiting Tests

### Brute Force Login
```bash
#!/bin/bash
for password in password 123456 admin root; do
  response=$(curl -s -d "user=admin&pass=$password" https://example.com/login)
  echo "$password: $response"
done
```

**Problem**: No rate limiting allows fast attempts

### API Endpoint Abuse
```bash
# Hammer API endpoint
for i in {1..1000}; do
  curl https://example.com/api/users &
done
wait
```

**Problem**: Excessive requests cause DoS or data exfiltration

### Test for Rate Limiting
```bash
#!/bin/bash
for i in {1..30}; do
  response=$(curl -s -w "\n%{http_code}" https://example.com/api/endpoint)
  echo "Request $i: $(echo "$response" | tail -n1)"
done
```

**Good**: 429 (Too Many Requests) after threshold
**Bad**: 200 OK for all requests

## HTTPS & TLS Testing

### Certificate Validation
```bash
# Check certificate validity
openssl s_client -connect example.com:443 -showcerts

# Look for:
# - Valid dates
# - Correct hostname
# - Chain of trust
```

### SSL/TLS Version
```bash
# Test for old protocols
openssl s_client -connect example.com:443 -ssl3
openssl s_client -connect example.com:443 -tls1

# Should fail for TLS < 1.2
```

**Requirement**: TLS 1.2+ only

### Cipher Strength
```bash
# Test weak ciphers
nmap --script ssl-enum-ciphers -p 443 example.com
```

**Bad**: NULL, EXPORT, DES, RC4
**Good**: ECDHE with AES-GCM

## File Upload Testing

### Test Cases
```bash
# Upload executable
curl -F "file=@shell.php" https://example.com/upload

# Upload with null byte bypass (old systems)
curl -F "file=@shell.php%00.txt" https://example.com/upload

# Upload large file
curl -F "file=@largefile" https://example.com/upload  # DoS risk
```

**Vulnerabilities**:
- Executable files allowed (php, exe, sh)
- No size limits (server exhaustion)
- Files accessible via web
- MIME type not validated

## API Testing

### Broken Object Level Authorization
```bash
# Get user 1's data
curl https://example.com/api/users/1 -H "Authorization: Bearer token"

# Try accessing user 2's data with same token
curl https://example.com/api/users/2 -H "Authorization: Bearer token"
```

### Excessive Data Exposure
```bash
curl https://example.com/api/users/1 | jq .
# Does response contain unnecessary fields?
# - password_hash
# - internal_notes
# - phone_number
```

### Mass Assignment
```bash
curl -X POST https://example.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test","is_admin":true}'
# Should not be able to set is_admin
```

## Testing Automation

### Using OWASP ZAP
```bash
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://example.com \
  -r report.html
```

### Using Burp Suite
```bash
burpsuite --config-file=scan-config.json https://example.com
```

## Summary Checklist

- [ ] All security headers present (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Cookies secured (HttpOnly, Secure, SameSite)
- [ ] CORS configured correctly (not wildcard + credentials)
- [ ] No open redirects or bad whitelist
- [ ] No information disclosure (headers, stack traces, debug mode)
- [ ] Authentication required on protected resources
- [ ] Session management secure (timeout, randomness)
- [ ] Rate limiting on sensitive endpoints
- [ ] HTTPS enforced (TLS 1.2+, good ciphers)
- [ ] File upload validation (type, size, accessible)
- [ ] API authorization checks on objects
- [ ] No excessive data in responses

---

**Reference**: OWASP Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
