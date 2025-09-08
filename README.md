# Web Application Vulnerability Scanner

A comprehensive Python-based web vulnerability scanner designed to identify critical security vulnerabilities in web applications including SQL Injection, Cross-Site Scripting (XSS), CSRF, Directory Traversal, Security Headers, Session Security, and Sensitive Information Exposure.

---

## 🔍 Features

### **✅ Comprehensive Vulnerability Detection:**
- **SQL Injection (SQLi)** - Multiple payload testing with error-based detection
- **Cross-Site Scripting (XSS)** - Reflected XSS detection in GET parameters
- **Cross-Site Request Forgery (CSRF)** - Form analysis for missing CSRF tokens
- **Directory Traversal** - Path traversal vulnerability testing with multiple payloads
- **Open Redirect** - Unvalidated redirect vulnerability detection
- **Security Headers Analysis** - Missing critical security headers identification
- **Session Security Assessment** - Cookie security flag analysis
- **Sensitive Information Exposure** - Pattern-based detection of emails, phone numbers, SSNs, API keys

### **🚀 Advanced Scanning Capabilities:**
- **Intelligent Web Crawling** - Recursive URL discovery up to configurable depth
- **Multi-threaded Scanning** - Concurrent vulnerability testing for enhanced performance
- **Rate Limiting** - Built-in delays to avoid overwhelming target servers
- **Duplicate Prevention** - Advanced signature-based duplicate vulnerability filtering
- **Professional Logging** - Comprehensive logging with timestamps and error handling
- **Session Management** - Persistent session handling with custom headers

### **🎯 User-Friendly Interface:**
- **Color-coded Output** - Immediate vulnerability identification with colored console display
- **Detailed Reporting** - Comprehensive vulnerability reports with evidence and payload information
- **Real-time Feedback** - Live scanning progress and vulnerability discovery notifications
- **Structured Documentation** - Professional output suitable for security assessment reports

---

## 📋 Requirements

- **Python 3.7+**
- **Required Libraries:**
  ```
  requests
  beautifulsoup4
  colorama
  urllib3
  concurrent.futures
  logging
  typing
  ```

---

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/PARADOX-12/Cybersecurity_projects.git
   cd Cybersecurity_projects/vul_scanner
   ```

2. **Install required dependencies:**
   ```bash
   pip install requests beautifulsoup4 colorama urllib3
   ```

3. **Run the scanner:**
   ```bash
   python app.py <target_url>
   ```

---

## 💻 Usage

### **Basic Usage**
```bash
python app.py <target_url>
```

### **Examples**
```bash
# Scan a website with comprehensive vulnerability testing
python app.py https://example.com

# Scan a local development application
python app.py http://localhost:8080

# Scan with output logging
python app.py https://testsite.com 2>&1 | tee scan_results.log
```

---

## 🔧 How It Works

### **1. Initialization & Configuration**
- Configures professional logging with timestamps
- Sets up enhanced session management with custom headers
- Initializes rate limiting and multi-threading parameters
- Prepares vulnerability tracking and reporting systems

### **2. Web Crawling Phase**
- Starts recursive crawling from target URL
- Discovers internal pages up to specified depth (default: 3)
- Maintains visited URL tracking to prevent infinite loops
- Normalizes URLs to avoid duplicate scanning

### **3. Comprehensive Vulnerability Testing**

**🔴 SQL Injection Detection:**
- Tests multiple SQL injection payloads: `'`, `1' OR '1'='1'`, `' OR 1=1--`, `' UNION SELECT NULL--`
- Analyzes responses for database error messages (MySQL, PostgreSQL, SQLite, Oracle)
- Identifies vulnerable parameters in GET requests

**🟠 Cross-Site Scripting (XSS) Testing:**
- Injects various XSS payloads including script tags and event handlers
- Tests reflection of malicious scripts in application responses
- Checks for successful payload execution indicators

**🟡 CSRF Vulnerability Analysis:**
- Examines all forms for state-changing operations (POST, PUT, DELETE)
- Identifies missing CSRF protection tokens
- Analyzes form structure and security implementations

**🟢 Directory Traversal Testing:**
- Tests path traversal payloads: `../../../etc/passwd`, Windows paths, encoded variants
- Looks for successful file system access indicators
- Checks multiple encoding and bypass techniques

**🔵 Open Redirect Detection:**
- Tests common redirect parameters: `url`, `redirect`, `next`, `return`, `goto`, `continue`
- Injects malicious redirect URLs and analyzes HTTP redirect responses
- Identifies unvalidated redirect vulnerabilities

**🟣 Security Headers Assessment:**
- Verifies presence of critical security headers:
  - `X-Frame-Options` (Clickjacking protection)
  - `X-Content-Type-Options` (MIME sniffing protection)
  - `X-XSS-Protection` (XSS protection header)
  - `Strict-Transport-Security` (HTTPS enforcement)
  - `Content-Security-Policy` (CSP protection)
  - `Referrer-Policy` (Referrer policy)

**⚫ Session Security Analysis:**
- Examines cookies for security flags:
  - `Secure` flag for HTTPS-only transmission
  - `HttpOnly` flag to prevent XSS cookie access
  - `SameSite` attribute for CSRF protection

**🔶 Sensitive Information Detection:**
- Pattern-based detection using regex:
  - Email addresses
  - Phone numbers (US format)
  - Social Security Numbers
  - API keys and tokens

### **4. Advanced Reporting System**
- Generates unique signatures to prevent duplicate vulnerability reporting
- Provides detailed evidence including URLs, parameters, and successful payloads
- Color-coded console output for immediate threat identification
- Comprehensive scan statistics and summary

---

## ⚙️ Configuration

### **Customizable Parameters**
```python
# Default configuration in app.py
max_depth = 3              # Maximum crawling depth
request_delay = 0.5        # Delay between requests (seconds)
max_workers = 3            # Concurrent thread limit for rate limiting
```

### **Session Configuration**
```python
# Enhanced session headers
'User-Agent': 'WebVulScanner/1.0 (Security Testing Tool)'
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
'Accept-Language': 'en-US,en;q=0.5'
'Accept-Encoding': 'gzip, deflate'
'Connection': 'keep-alive'
```

---

## 📊 Sample Output

```bash
2025-09-08 20:15:23,123 - INFO - Starting comprehensive security scan of https://example.com

[VULNERABILITY FOUND]
type: CSRF Vulnerability
url: https://example.com/login
form_action: /login
form_method: POST
description: Form lacks CSRF protection token

[VULNERABILITY FOUND]
type: Missing Security Header
url: https://example.com
header: X-Frame-Options
description: Missing clickjacking protection

[VULNERABILITY FOUND]
type: SQL Injection
url: https://example.com/search?id=1
parameter: id
payload: ' OR 1=1--

[VULNERABILITY FOUND]
type: Directory Traversal
url: https://example.com/file?path=test
parameter: path
payload: ../../../etc/passwd

[VULNERABILITY FOUND]
type: Sensitive Information Exposure
url: https://example.com/contact
info_type: email
leaked_value: admin@example.com

Scan Complete!
Total URLs scanned: 15
Vulnerabilities found: 12
```

---

## 🛡️ Security & Ethics

### ⚠️ **CRITICAL DISCLAIMER**
This tool is designed **exclusively for:**
- ✅ **Educational and learning purposes**
- ✅ **Authorized penetration testing with written permission**
- ✅ **Security assessments on owned systems**
- ✅ **CTF competitions and practice labs**
- ✅ **Internal security audits with proper authorization**

### 🚫 **STRICTLY PROHIBITED:**
- ❌ **Unauthorized scanning of third-party websites**
- ❌ **Testing systems without explicit written permission**
- ❌ **Any illegal or malicious activities**
- ❌ **Production systems without proper authorization**
- ❌ **Violating terms of service or applicable laws**

### 🔒 **Responsible Usage Guidelines:**
- **Always obtain written permission** before testing any system
- **Use only in controlled environments** with proper isolation
- **Respect rate limits** and server resources to avoid DoS
- **Follow responsible disclosure** for any genuine findings
- **Comply with local laws** and organizational policies
- **Document all testing** with proper authorization trails

---

## 🧪 Testing & Validation

### **Recommended Test Environments:**
- **DVWA (Damn Vulnerable Web Application)** - Comprehensive vulnerability testing
- **WebGoat by OWASP** - Interactive security lessons
- **Mutillidae II** - Intentionally vulnerable web application
- **TryHackMe vulnerable machines** - Practical security challenges
- **Local test applications** - Custom vulnerable applications

### **Validation Methodology:**
1. **Test against known vulnerable applications** to verify detection accuracy
2. **Manual verification** of automated findings
3. **False positive analysis** and tuning
4. **Performance testing** under various load conditions
5. **Cross-platform compatibility** testing

---

## 🔧 Technical Architecture

### **Core Components:**
- **`webVulScanner` Class** - Main scanner orchestration
- **Crawling Engine** - Recursive URL discovery system
- **Vulnerability Modules** - Specialized testing for each vulnerability type
- **Reporting System** - Comprehensive finding documentation
- **Session Management** - HTTP session handling and optimization

### **Key Technical Features:**
- **Multi-threaded Architecture** - Concurrent vulnerability testing
- **Rate Limiting** - Configurable delays to prevent server overload
- **Error Handling** - Robust exception management and logging
- **Memory Optimization** - Efficient URL tracking and session reuse
- **Extensible Design** - Modular structure for adding new vulnerability tests

---

## 📈 Performance Specifications

- **Concurrent Threads:** 3 (optimized for rate limiting)
- **Request Delay:** 0.5 seconds (configurable)
- **Memory Efficient:** Session reuse and optimized data structures
- **Scalable:** Handles websites with hundreds of pages
- **Fast Detection:** Parallel vulnerability testing across multiple URLs
- **Professional Logging:** Timestamped activity tracking

---

## 🎯 Professional Applications

### **Suitable For:**
- **Security Assessment Documentation** - Professional vulnerability reports
- **Penetration Testing** - Initial vulnerability discovery phase
- **Security Training** - Educational demonstration of common vulnerabilities
- **Compliance Auditing** - Security control validation
- **Bug Bounty Research** - Automated initial reconnaissance

### **Industry Alignment:**
- **OWASP Top 10** vulnerability coverage
- **Security Assessment** methodology compliance
- **Penetration Testing** industry standards
- **Cybersecurity Education** practical skill development

---

## 📝 Project Recognition

This comprehensive vulnerability scanner was developed as part of a **cybersecurity internship program**, demonstrating practical application of:

- **OWASP Top 10** vulnerability identification and testing
- **Automated security testing** principles and implementation  
- **Python security tool development** with professional coding standards
- **Multi-threaded application architecture** for performance optimization
- **Professional documentation** and security assessment reporting

The project showcases **industry-ready skills** in vulnerability assessment, automated testing, and security tool development suitable for **SOC analyst**, **penetration tester**, and **security consultant** roles.

---

## 📜 License & Legal

This project is licensed for **educational and authorized security testing purposes only**. 

**Legal Notice:** Unauthorized vulnerability scanning may violate local laws, terms of service, and organizational policies. Users are solely responsible for ensuring proper authorization before testing any systems.

