# Advanced SQL Injection Scanner 🛡️

A comprehensive, feature-rich SQL injection scanner designed for security professionals and penetration testers. This tool provides automated detection, exploitation, and reporting of SQL injection vulnerabilities with advanced features including authentication handling, proxy integration, and database dumping capabilities.

## 🚀 Features

### 📌 A) URL Parameter Discovery
- **Auto crawl** all URLs, forms, and API endpoints
- **Auto detect** GET & POST parameters
- **Parse hidden fields** in forms
- **Configurable crawl depth** (--crawl=3)
- **HTML parser** using BeautifulSoup
- **JavaScript parsing** for dynamic content
- **API endpoint discovery**

### 📌 B) Payload Generator
- **Comprehensive payload library** with 200+ payloads
- **Error-based** injection payloads
- **Union-based** injection payloads  
- **Boolean-based blind** injection payloads
- **Time-based blind** injection payloads
- **Stacked queries** payloads
- **WAF bypass** techniques
- **Custom payload** support from files
- **DBMS-specific** payloads (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)

### 📌 C) Injection Engine
- **Multi-threaded** testing for performance
- **Parameter loop** testing
- **Payload delivery** with various methods
- **Response recording** (time, body, headers)
- **Baseline comparison** for accurate detection
- **Rate limiting** and WAF detection
- **Retry mechanisms** for reliability

### 📌 D) Response Analyzer
- **Pattern matching** for database errors
- **Time delay** analysis for time-based attacks
- **Content anomaly** detection
- **Regex signatures** for different DBMS:
  - MySQL: "You have an error in your SQL syntax"
  - MSSQL: "Unclosed quotation mark"
  - Oracle: "ORA-00933"
  - PostgreSQL: "syntax error at or near"
  - SQLite: "SQLITE_ERROR"

### 📌 E) DBMS Fingerprinting
- **Automatic DBMS detection** from error messages
- **Version banner** extraction
- **Database fingerprinting** techniques
- **Support for major DBMS** (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)

### 📌 F) Automatic Database Dumping
- **UNION SELECT** payload construction
- **Database name** extraction (SELECT database())
- **Table name** extraction (INFORMATION_SCHEMA)
- **Column enumeration**
- **Data dumping** with row iteration
- **Blind data extraction** for blind injection scenarios

### 📌 G) Authentication Flow
- **Cookie/session** handling
- **Auto login** with form detection
- **CSRF bypass** techniques
- **JWT/Bearer token** support
- **Custom header** support
- **Session maintenance**

### 📌 H) Proxy Integration
- **Burp Suite** integration
- **OWASP ZAP** integration
- **Custom proxy** support
- **CORS bypass** techniques
- **Traffic interception** and logging

### 📌 I) Threading & Rate Control
- **Multi-threading** support (configurable)
- **Request rate limiting**
- **WAF detection** and auto-slowdown
- **Adaptive delay** mechanisms
- **Burst control**

### 📌 J) Logging & Reporting
- **Comprehensive logging** of all requests/responses
- **Vulnerability highlighting**
- **Multiple export formats** (JSON, HTML, TXT)
- **Executive summaries**
- **Detailed technical reports**

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
cd advanced-sqli-scanner
pip install -r requirements.txt
```

### Install Playwright (for JavaScript-heavy sites)
```bash
playwright install
```

## 📖 Usage

### Quick Start (Interactive Examples)
```bash
# Basic scan (interactive - will prompt for target)
python examples/basic_scan.py

# Advanced scan with multiple features
python examples/advanced_scan.py
```

### Command Line Usage
```bash
# Scan a single URL
python main.py -u "https://your-target.com/page.php?id=1"

# Scan with forms included
python main.py -u "https://your-target.com/" --forms

# Scan multiple URLs from file
python main.py -l urls.txt

# Scan with custom crawl depth
python main.py -u "https://your-target.com/" --crawl 3
```

### Safe Testing Environments

For safe testing and learning, use these vulnerable applications:

- **DVWA**: `http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit`
- **bWAPP**: `http://localhost/bWAPP/sqli_1.php?title=1&action=search`
- **Mutillidae**: `http://localhost/mutillidae/index.php?page=user-info.php&username=admin`
- **SQLi Labs**: `http://localhost/sqli-labs/Less-1/?id=1`
- **WebGoat**: `http://localhost:8080/WebGoat/start.mvc`

**⚠️ Important**: Only test on applications you own or have explicit permission to test.

### Advanced Usage
```bash
# Authenticated scanning
python main.py -u "http://example.com/admin/" \
  --auth-url "http://example.com/login.php" \
  --username "admin" --password "password"

# Scan with custom payloads
python main.py -u "http://example.com/page.php?id=1" \
  --payloads payloads/custom_payloads.txt

# Scan through Burp Suite proxy
python main.py -u "http://example.com/page.php?id=1" \
  --proxy "http://127.0.0.1:8080"

# Target specific DBMS
python main.py -u "http://example.com/page.php?id=1" \
  --dbms mysql

# Multi-threaded scanning with custom delay
python main.py -u "http://example.com/" \
  --threads 10 --delay 0.5

# Generate HTML report
python main.py -u "http://example.com/page.php?id=1" \
  --format html -o results/
```

### Command Line Options
```
Target Options:
  -u, --url URL          Target URL to scan
  -l, --list FILE        File containing list of URLs

Crawling Options:
  --crawl DEPTH          Crawl depth (default: 2)
  --forms                Include forms in scan
  --cookies COOKIES      Custom cookies (name=value;name2=value2)

Authentication Options:
  --auth-url URL         Authentication URL for login
  --username USER        Username for authentication
  --password PASS        Password for authentication
  --headers HEADERS      Custom headers (Header:Value;Header2:Value2)

Scanning Options:
  --threads NUM          Number of threads (default: 5)
  --delay SECONDS        Delay between requests (default: 1.0)
  --timeout SECONDS      Request timeout (default: 10)

Payload Options:
  --payloads FILE        Custom payload file
  --dbms TYPE            Target DBMS (mysql/mssql/oracle/postgresql/sqlite)

Proxy Options:
  --proxy URL            Proxy URL (http://host:port)
  --proxy-auth USER:PASS Proxy authentication

Output Options:
  -o, --output DIR       Output directory for results
  --format FORMAT        Output format (json/html/txt)
  -v, --verbose          Verbose output
```

## 🔧 Configuration

### Custom Payloads
Create custom payload files in the format:
```
payload|type|dbms|description
' OR '1'='1|error_based|generic|Classic OR injection
' UNION SELECT NULL--|union_based|generic|Basic UNION test
```

### Scanner Configuration
Modify `config/scanner_config.json` to customize:
- Detection thresholds
- Rate limiting settings
- Output preferences
- Advanced options

## 📊 Examples

### Basic Scanning Example
```python
from src.scanner import SQLiScanner

# Initialize scanner
scanner = SQLiScanner(
    crawl_depth=2,
    threads=5,
    delay=1.0,
    verbose=True
)

# Perform scan
results = scanner.scan_url("http://example.com/page.php?id=1")

# Display results
scanner.display_summary(results)

# Export reports
scanner.export_results('html', 'scan_report.html')
```

### Advanced Scanning Example
```python
# Authenticated scan with proxy
scanner = SQLiScanner(
    proxy="http://127.0.0.1:8080",
    threads=10,
    delay=0.5
)

results = scanner.scan_url(
    url="http://example.com/admin/",
    auth_url="http://example.com/login.php",
    username="admin",
    password="password",
    custom_payloads="payloads/custom_payloads.txt"
)
```

## 🔍 Detection Techniques

### Error-Based Detection
- Database error message analysis
- DBMS-specific error patterns
- Syntax error identification

### Time-Based Detection
- Response time analysis
- Configurable delay thresholds
- Statistical anomaly detection

### Boolean-Based Detection
- Response content comparison
- Length-based analysis
- Status code variations

### Union-Based Detection
- Column count enumeration
- Data extraction verification
- Information schema access

## 🛡️ Security Features

### WAF Bypass Techniques
- Comment-based bypasses (`/**/`)
- Encoding bypasses (URL, HTML, Hex)
- Case variation bypasses
- Whitespace manipulation

### Authentication Bypass
- CSRF token extraction and bypass
- Session management
- JWT token handling
- Cookie manipulation

### Proxy Integration
- Burp Suite Professional integration
- OWASP ZAP integration
- Custom proxy chains
- CORS bypass techniques

## 📈 Reporting

### Report Formats
- **JSON**: Machine-readable detailed results
- **HTML**: Interactive web-based reports
- **TXT**: Plain text summaries

### Report Contents
- Executive summary
- Vulnerability details
- Database dump results
- Scan statistics
- Remediation recommendations

## 🚨 Vulnerability Types Detected

- **Error-based SQL Injection**
- **Union-based SQL Injection**
- **Boolean-based Blind SQL Injection**
- **Time-based Blind SQL Injection**
- **Second-order SQL Injection**
- **Header-based SQL Injection**
- **Cookie-based SQL Injection**
- **Stacked Queries**

## 🎯 Supported Databases

- **MySQL / MariaDB**
- **Microsoft SQL Server**
- **Oracle Database**
- **PostgreSQL**
- **SQLite**
- **Generic SQL databases**

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for complying with applicable laws and regulations. Only test systems you own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)

## 📞 Support

For support, questions, or feature requests, please open an issue on the project repository.

---

**Happy Hunting! 🎯**
