# SAST Vulnerability Patterns by Language

Specific code patterns that indicate security vulnerabilities.

## JavaScript / TypeScript

### SQL Injection
```javascript
// PATTERN: String concatenation in SQL
query = "SELECT * FROM users WHERE id=" + userId;
query = `SELECT * FROM users WHERE id=${userId}`;

// FIX:
query = db.prepare("SELECT * FROM users WHERE id=?");
query.run(userId);
```

### Command Injection
```javascript
// PATTERN: exec/spawn with string input
exec('ls ' + userDir);
spawn('cat', [userInput]);  // Actually safe, args are array

// FIX:
spawn('ls', ['-la', userDir]);
```

### XSS via dangerouslySetInnerHTML
```javascript
// PATTERN: React
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// PATTERN: jQuery
$('#content').html(userInput);

// FIX: React
<div>{userComment}</div>

// FIX: jQuery
$('#content').text(userInput);
```

### Hardcoded Secrets
```javascript
// PATTERN:
const apiKey = "sk_live_abc123def456";
const secret = "mysecret_password";

// FIX:
const apiKey = process.env.STRIPE_API_KEY;
```

### Missing CSRF Tokens
```javascript
// PATTERN: No CSRF check on POST
app.post('/transfer-money', (req, res) => {
  transferFunds(req.body);
});

// FIX:
app.post('/transfer-money', csrfProtection, (req, res) => {
  transferFunds(req.body);
});
```

### Weak Cryptography
```javascript
// PATTERN:
const hash = require('crypto').createHash('md5');
const token = Math.random().toString(36);

// FIX:
const hash = require('crypto').createHash('sha256');
const token = require('crypto').randomBytes(32).toString('hex');
```

### Insecure Deserialization
```javascript
// PATTERN: eval with user input
const code = "user_input_here";
eval(code);

// PATTERN: Function constructor
new Function("return " + userInput)();

// FIX:
JSON.parse(userInput);
```

### Path Traversal
```javascript
// PATTERN: No normalization
const fs = require('fs');
fs.readFile(baseDir + userPath);

// FIX:
const path = require('path');
const safe = path.join(baseDir, userPath);
if (!safe.startsWith(baseDir)) throw new Error('Invalid path');
fs.readFile(safe);
```

## Python

### SQL Injection
```python
# PATTERN: String formatting
query = f"SELECT * FROM users WHERE email='{email}'"
query = "SELECT * FROM users WHERE email='" + email + "'"

# FIX:
cursor.execute("SELECT * FROM users WHERE email=?", (email,))
# Or with SQLAlchemy ORM
User.query.filter_by(email=email).all()
```

### Command Injection
```python
# PATTERN: shell=True allows injection
import subprocess
subprocess.run(f"grep {pattern} {file}", shell=True)

# PATTERN: os.system
os.system(f"rm {user_file}")

# FIX:
subprocess.run(['grep', pattern, file], capture_output=True)
subprocess.run(['rm', user_file], capture_output=True)
```

### Unsafe Deserialization
```python
# PATTERN: pickle with untrusted data
import pickle
data = pickle.loads(request.data)

# PATTERN: eval
code = request.args.get('code')
eval(code)

# FIX:
import json
data = json.loads(request.data)
```

### Weak Password Hashing
```python
# PATTERN:
import hashlib
hash = hashlib.md5(password).hexdigest()

# PATTERN: Direct hashing
import hashlib
hash = hashlib.sha256(password).hexdigest()

# FIX:
from werkzeug.security import generate_password_hash
hash = generate_password_hash(password, method='pbkdf2:sha256')

# Or:
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### Hardcoded Secrets
```python
# PATTERN:
SECRET_KEY = 'super_secret_key_2026'
DATABASE_URL = 'postgresql://user:password@localhost/db'
STRIPE_KEY = 'sk_live_123456789'

# FIX:
import os
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY = os.environ['SECRET_KEY']
```

### Debug Mode in Production
```python
# PATTERN: Flask debug mode enabled
if __name__ == '__main__':
    app.run(debug=True)  # Never in production!

# PATTERN: Django debug
DEBUG = True  # In settings.py

# FIX:
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
```

### Insecure JWT Verification
```python
# PATTERN: Verification disabled
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# PATTERN: No key validation
payload = jwt.decode(token, "secret")  # Should use strong key

# FIX:
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

### Path Traversal
```python
# PATTERN: No normalization
import os
file = open(basedir + user_path, 'r')

# FIX:
import os
safepath = os.path.normpath(os.path.join(basedir, user_path))
if not safepath.startswith(basedir):
    raise ValueError("Path traversal detected")
file = open(safepath, 'r')
```

### SSRF: No URL Validation
```python
# PATTERN: External URL fetch without validation
import requests
url = request.args.get('url')
response = requests.get(url)  # Could be http://169.254.169.254/

# FIX:
from urllib.parse import urlparse
url = request.args.get('url')
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError('Invalid host')
response = requests.get(url)
```

## Java

### SQL Injection
```java
// PATTERN: String concatenation
String query = "SELECT * FROM users WHERE id=" + id;
Statement stmt = connection.createStatement();
stmt.executeQuery(query);

// FIX:
String query = "SELECT * FROM users WHERE id=?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, id);
pstmt.executeQuery();
```

### Unsafe Reflection
```java
// PATTERN: Loading untrusted class names
String className = request.getParameter("class");
Class.forName(className);

// PATTERN: Unsafe method invocation
Class<?> cls = Class.forName(className);
Method method = cls.getMethod(methodName);
method.invoke(obj);

// FIX: Use whitelist
String className = request.getParameter("class");
if (!ALLOWED_CLASSES.contains(className)) {
    throw new SecurityException("Disallowed class");
}
```

### Hardcoded Credentials
```java
// PATTERN:
String password = "admin123";
String apiKey = "sk_live_abc123def456";

// FIX:
String password = System.getenv("DB_PASSWORD");
String apiKey = System.getenv("STRIPE_API_KEY");
```

### Insecure Deserialization
```java
// PATTERN:
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // Can execute arbitrary code

// FIX: Use JSON instead
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(json, User.class);
```

### XXE (XML External Entity)
```java
// PATTERN: Unsafe XML parsing
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(input);  // XXE vulnerable

// FIX:
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(input);
```

## Go

### SQL Injection
```go
// PATTERN: String concatenation
query := fmt.Sprintf("SELECT * FROM users WHERE id=%d", userID)
db.Query(query)

// FIX:
query := "SELECT * FROM users WHERE id=?"
db.Query(query, userID)
```

### Command Injection
```go
// PATTERN: Passing user input to shell
cmd := exec.Command("bash", "-c", "grep "+pattern+" "+file)

// FIX:
cmd := exec.Command("grep", pattern, file)
```

### Weak TLS Verification
```go
// PATTERN: Insecure TLS
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,  // Never do this!
        },
    },
}

// FIX:
client := &http.Client{}  // Default is secure
```

## Rust

### Buffer Overflows
```rust
// PATTERN: Unsafe memory operations
unsafe {
    let ptr = malloc(size);
    memcpy(ptr, data, size + 100);  // Buffer overflow!
}

// FIX:
let mut buffer = vec![0u8; size];
buffer.copy_from_slice(&data[..size]);
```

### Unsafe Deserialization
```rust
// PATTERN: Deserialize untrusted data
let data: MyStruct = serde_json::from_str(user_input)?;

// FIX: Use validation after deserialization
let data: MyStruct = serde_json::from_str(user_input)?;
data.validate()?;
```

## Common Patterns Across Languages

### Weak Random Number Generation
```
- Math.random() (JavaScript)
- random.randint() (Python)
- rand() (C/C++)
- new Random() without seed (Java)

FIX: Use cryptographic RNG
- crypto.randomBytes() (JavaScript)
- secrets module (Python)
- getrandom() (Rust)
```

### Logging Sensitive Data
```
- logger.info("User: " + username + " password: " + password)
- console.log("API key:", apiKey)
- print(f"SSN: {ssn}")

FIX: Filter sensitive data before logging
```

### Missing Input Validation
```
- No length checks
- No type checks
- No range validation
- No whitelist checks

FIX: Validate on server-side
```

### Weak Cryptographic Algorithms
```
- MD5, SHA1, DES, RC4
- 64-bit encryption
- ECB mode (same plaintext = same ciphertext)

FIX: Use strong algorithms
- SHA256 or stronger
- RSA 2048+ or ECC
- CBC/GCM modes
```

---

**Note**: These patterns are common indicators but may have false positives. Always review findings in context.
