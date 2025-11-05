# Darkly

A comprehensive web security project exploring common vulnerabilities through hands-on exploitation and documentation.

## Overview

**Darkly** is a web security training project from 42 School that challenges students to identify and exploit 14 distinct vulnerabilities in a deliberately insecure web application. This project provides practical experience in offensive security techniques and emphasizes the importance of secure coding practices.

### Learning Objectives
- Identify common web vulnerabilities in real-world scenarios
- Understand attack vectors and exploitation techniques
- Develop defensive security mindset through offensive practice
- Document vulnerabilities with detailed explanations and prevention measures

## OWASP Top 10 Coverage

This project addresses multiple categories from the [OWASP Top 10](https://owasp.org/www-project-top-ten/) - the industry-standard awareness document for web application security risks:

| OWASP Category | Breaches in This Project |
|----------------|--------------------------|
| **A01:2021 – Broken Access Control** | #07 Open Redirect, #10 Forgot Password, #11 Directory Manipulation, #12 Cookie Token |
| **A02:2021 – Cryptographic Failures** | #01 Sensitive Data Exposure, #12 Cookie Token (weak hashing) |
| **A03:2021 – Injection** | #02 SQL Injection (Members), #03 SQL Injection (Images), #05 XSS Media, #06 Stored XSS |
| **A04:2021 – Insecure Design** | #09 Integer Input Validation, #12 Cookie Token Manipulation |
| **A05:2021 – Security Misconfiguration** | #01 Sensitive Data (robots.txt), #08 Hidden Directory, #13 Header Hijack |
| **A07:2021 – Identification and Authentication Failures** | #04 Brute Force Login, #10 Forgot Password Validation |
| **A08:2021 – Software and Data Integrity Failures** | #14 File Sanitation (unrestricted upload) |

## Project Structure

```
Darkly/
├── 01_sensitive_data_exposure/
│   ├── flag
│   └── Resources/
│       ├── explanation.md (English)
│       ├── explanation_korean.md (Korean)
│       └── images/
├── 02_sql_injection/
│   ├── flag
│   └── Resources/
│       ├── explanation.md
│       ├── explanation_korean.md
│       └── images/
├── ...
└── 14_file_sanitation/
    ├── flag
    └── Resources/
        ├── explanation.md
        ├── explanation_korean.md
        ├── images/
        └── upload_exploit.js
```

## Discovered Vulnerabilities

### ✅ Completed (14/14)

1. **Sensitive Data Exposure** - Information disclosure via robots.txt, directory listing, and exposed credentials
2. **SQL Injection (Members)** - Database manipulation through UNION SELECT attacks on member search
3. **SQL Injection (Images)** - Data exfiltration via UNION SELECT on image gallery
4. **Brute Force Login** - Authentication bypass through automated password attacks (no rate limiting)
5. **Reflected XSS (Media)** - Cross-site scripting via data URI injection in media source
6. **Stored XSS (Feedback)** - Persistent XSS through unvalidated feedback form input
7. **Open Redirect** - URL redirection vulnerability in social media links
8. **Hidden Directory Exposure** - Sensitive files accessible through directory indexing and robots.txt disclosure
9. **Integer Input Validation** - Client-side validation bypass leading to data manipulation
10. **Forgot Password Validation** - Authentication bypass through missing server-side validation
11. **Directory Manipulation (Path Traversal)** - Arbitrary file access via `../` sequences
12. **Cookie Token Manipulation** - Privilege escalation through weak MD5 hashing and client-side auth
13. **HTTP Header Hijack** - Access control bypass via User-Agent and Referer header manipulation
14. **File Sanitation Bypass** - Unrestricted file upload with Content-Type validation weakness

## Documentation

Each vulnerability includes:
- **flag** - The captured flag proving successful exploitation
- **explanation.md** - Comprehensive English documentation covering:
  - Vulnerability overview and risk assessment
  - Step-by-step discovery and exploitation process
  - Technical explanation of the security flaw
  - Multiple attack scenarios
  - Prevention measures with code examples
  - Real-world impact cases
  - Security best practices
  - References to OWASP and CWE standards
- **explanation_korean.md** - Complete Korean translation with additional context
- **images/** - Screenshots documenting the exploitation process
- **Additional resources** - Exploit scripts and tools where applicable

## Key Takeaways

### Security Principles Demonstrated
1. **Never Trust Client Input** - All user input must be validated server-side
2. **Defense in Depth** - Multiple security layers prevent single-point failures
3. **Principle of Least Privilege** - Minimize access rights to essential operations only
4. **Fail Securely** - Systems should fail in a secure manner, not expose vulnerabilities
5. **Security by Design** - Build security into the application from the start, not as an afterthought

### Common Vulnerability Patterns
- **Input Validation Failures** - SQL injection, XSS, path traversal, integer overflow
- **Authentication Weaknesses** - Brute force, weak password reset, session management
- **Authorization Flaws** - IDOR, privilege escalation, access control bypass
- **Cryptographic Failures** - Weak hashing (MD5), unsalted passwords, predictable tokens
- **Configuration Issues** - Directory listing, exposed files, verbose errors

## Tools & Techniques Used

- **Manual Testing** - Browser DevTools, HTML/Cookie manipulation
- **Automated Tools** - curl, Burp Suite, hash crackers
- **Reconnaissance** - robots.txt analysis, directory enumeration, HTML source inspection
- **Exploitation** - SQL injection, XSS payloads, path traversal, header manipulation
- **Cryptanalysis** - MD5 hash cracking, token prediction

## Prevention Summary

### Essential Security Measures
1. **Input Validation** - Validate all input server-side with whitelists
2. **Output Encoding** - Escape all output to prevent injection attacks
3. **Parameterized Queries** - Use prepared statements to prevent SQL injection
4. **Strong Authentication** - Implement proper session management and MFA
5. **Access Control** - Enforce server-side authorization checks
6. **Secure Configuration** - Disable directory listing, secure error handling
7. **HTTPS Everywhere** - Encrypt all communications
8. **Security Headers** - Use CSP, X-Frame-Options, HSTS, etc.
9. **Regular Updates** - Keep all software and dependencies current
10. **Security Testing** - Conduct regular penetration testing and code reviews

## Timeline

- **Started**: 2025-10-29
- **Completed**: 2025-11-05
- **Total Duration**: 7 days
- **Vulnerabilities Found**: 14/14
- **Documentation**: 28 files (14 English + 14 Korean)

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Disclaimer

This project is for **educational purposes only**. All techniques documented here were performed in a controlled environment on an intentionally vulnerable application designed for security training. Never attempt to exploit vulnerabilities on systems without explicit authorization.

---

*42 School Security Project - Building secure applications through understanding vulnerabilities*
