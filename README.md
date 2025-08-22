# Web Vulnerability Scanner

A simple Python-based web vulnerability scanner to help identify common security issues such as SQL Injection, Cross-Site Scripting (XSS), Sensitive Information Exposure, and potential vulnerabilities by crawling a target website.

---

## Features

- Crawls a website up to a configurable depth to discover URLs.
- Detects potential SQL Injection vulnerabilities using common payloads.
- Detects Cross-Site Scripting (XSS) vulnerabilities in GET parameters.
- Checks for exposed sensitive information like emails, phone numbers, SSNs, and API keys.
- Multi-threaded scanning for faster results.
- Colored console output for easy identification of vulnerabilities.

---

## Requirements

- Python 3.7+
- `requests` library
- `beautifulsoup4` library
- `colorama` library

---

## Installation

1. Clone this repository or copy the scanner script.
2. Install the required Python packages:

```bash
pip install requests beautifulsoup4 colorama
```

---

## Usage

Run the scanner with the target URL as an argument:

```bash
python scanner.py <target_url>
```

Example:

```bash
python scanner.py https://example.com
```

---

## How It Works

1. **Crawl:** The scanner crawls the provided target URL to a maximum depth (default 3) to find all internal pages.
2. **Scan:** For each discovered URL, it tests:
   - SQL Injection by injecting common payloads into GET parameters.
   - XSS by injecting script payloads into GET parameters.
   - Sensitive information leaks by scanning the page content.
3. **Report:** Any vulnerabilities found are printed to the console with details.

---

## Configuration

- **Max depth:** You can change the crawling depth by modifying the `max_depth` parameter in the `webVulScanner` initialization.
- **Payloads & patterns:** Payloads for SQL Injection, XSS, and regex patterns for sensitive information can be customized in the source code.

---

## Disclaimer

This tool is intended **for educational purposes and authorized security testing only**. Unauthorized scanning or exploitation of websites is illegal and unethical. Always obtain proper permission before running this scanner against any target.


---

## Contact

For any questions or suggestions, feel free to open an issue or contact the author.