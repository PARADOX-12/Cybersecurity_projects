import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set
import logging


class webVulScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()

    def normalize_url(self, url: str) -> str:
        """Normalize the URL to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def crawl(self, url: str, depth: int = 0) -> None:
        """
        Crawl the website to discover pages and endpoints.

        Args:
        url: Current URL to crawl
        depth: Current depth in the crawl tree
        """
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links in the page
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")
            

    def check_sql_injection(self, url: str) -> None:
        """Test for potential SQL injection vulnerabilities"""
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

        for payload in sql_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={payload}")
                    response = self.session.get(test_url)

                    # Look for SQL error messages
                    if any(error in response.text.lower() for error in 
                        ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")


    def check_xss(self, url: str) -> None:
        """Test for potential Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in xss_payloads:
            try:
                # Test GET parameters
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")


    def check_sensitive_info(self, url: str) -> None:
        """Check for exposed sensitive information"""
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }

        try:
            response = self.session.get(url)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    leaked_value = match.group(0)  # get the actual matched text
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'leaked_value': leaked_value
                    })

        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")
    

    def check_csrf(self, url: str) -> None:
    # Check for CSRF vulnerabilities by analyzing forms and tokens
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms in the page
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                # Check if form modifies data (POST, PUT, DELETE)
                if form_method in ['POST', 'PUT', 'DELETE']:
                    # Look for CSRF tokens
                    csrf_tokens = form.find_all(['input'], attrs={
                        'name': re.compile(r'csrf|token|authenticity', re.I),
                        'type': 'hidden'
                    })
                    
                    if not csrf_tokens:
                        self.report_vulnerability({
                            'type': 'CSRF Vulnerability',
                            'url': url,
                            'form_action': form_action,
                            'form_method': form_method,
                            'description': 'Form lacks CSRF protection token'
                        })
                        
        except Exception as e:
            print(f"Error checking CSRF on {url}: {str(e)}")


    def check_directory_traversal(self, url: str) -> None:
    # Test for directory traversal vulnerabilities
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
    
        for payload in traversal_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                        f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url)
                    
                    # Check for signs of successful directory traversal
                    if any(indicator in response.text.lower() for indicator in 
                        ['root:', 'daemon:', '[boot loader]', 'localhost']):
                        self.report_vulnerability({
                            'type': 'Directory Traversal',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
                        
            except Exception as e:
                print(f"Error testing directory traversal on {url}: {str(e)}")



    def check_security_headers(self, url: str) -> None:
    # Check for missing security headers
        try:
            response = self.session.get(url)
            headers = response.headers
            
            # Important security headers to check
            security_headers = {
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-Content-Type-Options': 'Missing MIME type sniffing protection',
                'X-XSS-Protection': 'Missing XSS protection header',
                'Strict-Transport-Security': 'Missing HTTPS enforcement',
                'Content-Security-Policy': 'Missing CSP protection',
                'Referrer-Policy': 'Missing referrer policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self.report_vulnerability({
                        'type': 'Missing Security Header',
                        'url': url,
                        'header': header,
                        'description': description
                    })
                    
        except Exception as e:
            print(f"Error checking security headers on {url}: {str(e)}")



    def check_open_redirect(self, url: str) -> None:
    # Test for open redirect vulnerabilities
        redirect_payloads = [
            "http://evil.com",
            "https://malicious.site",
            "//evil.com",
            "javascript:alert('redirect')"
        ]
    
        for payload in redirect_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                
                # Common redirect parameters
                redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'continue']
                
                for param in params:
                    if param.lower() in redirect_params:
                        test_url = url.replace(f"{param}={params[param][0]}", 
                                            f"{param}={urllib.parse.quote(payload)}")
                        
                        response = self.session.get(test_url, allow_redirects=False)
                        
                        if 300 <= response.status_code < 400:
                            location = response.headers.get('Location', '')
                            if payload in location or 'evil.com' in location:
                                self.report_vulnerability({
                                    'type': 'Open Redirect',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'redirect_location': location
                                })
                                
            except Exception as e:
                print(f"Error testing open redirect on {url}: {str(e)}")



    def check_session_security(self, url: str) -> None:
    # """Check for insecure session management"""
        try:
            response = self.session.get(url)
            
            # Check cookies for security flags
            for cookie in self.session.cookies:
                cookie_issues = []
                
                if not cookie.secure:
                    cookie_issues.append("Missing Secure flag")
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    cookie_issues.append("Missing HttpOnly flag")
                if not hasattr(cookie, 'samesite') or not cookie.samesite:
                    cookie_issues.append("Missing SameSite attribute")
                    
                if cookie_issues:
                    self.report_vulnerability({
                        'type': 'Insecure Cookie',
                        'url': url,
                        'cookie_name': cookie.name,
                        'issues': cookie_issues
                    })
                    
        except Exception as e:
            print(f"Error checking session security on {url}: {str(e)}")



    def check_session_security(self, url: str) -> None:
    # """Check for insecure session management"""
        try:
            response = self.session.get(url)
            
            # Check cookies for security flags
            for cookie in self.session.cookies:
                cookie_issues = []
                
                if not cookie.secure:
                    cookie_issues.append("Missing Secure flag")
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    cookie_issues.append("Missing HttpOnly flag")
                if not hasattr(cookie, 'samesite') or not cookie.samesite:
                    cookie_issues.append("Missing SameSite attribute")
                    
                if cookie_issues:
                    self.report_vulnerability({
                        'type': 'Insecure Cookie',
                        'url': url,
                        'cookie_name': cookie.name,
                        'issues': cookie_issues
                    })
                    
        except Exception as e:
            print(f"Error checking session security on {url}: {str(e)}")


    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.
        
        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        
        # Enhanced session configuration
        self.session.headers.update({
            'User-Agent': 'WebVulScanner/1.0 (Security Testing Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Rate limiting
        self.request_delay = 0.5  # seconds between requests
        
        # Initialize colorama for cross-platform colored output
        colorama.init()


    def scan(self) -> List[Dict]:
        """Main scanning method that coordinates the security checks"""
        print(f"\n{colorama.Fore.BLUE}Starting comprehensive security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")
    
        # First, crawl the website
        self.crawl(self.target_url)
        
        # Run all security checks
        with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced for rate limiting
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
                executor.submit(self.check_csrf, url)
                executor.submit(self.check_directory_traversal, url)
                executor.submit(self.check_security_headers, url)
                executor.submit(self.check_open_redirect, url)
                executor.submit(self.check_session_security, url)
                
                # Add small delay for rate limiting
                import time
                time.sleep(self.request_delay)
        
        return self.vulnerabilities


    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Record and display found vulnerabilities without duplicates"""
        # Create a unique signature for each vulnerability
        signature = f"{vulnerability.get('type')}|{vulnerability.get('url')}|{vulnerability.get('parameter', '')}|{vulnerability.get('info_type', '')}|{vulnerability.get('payload', '')}"

        if not hasattr(self, "_reported_signatures"):
            self._reported_signatures = set()

        if signature not in self._reported_signatures:
            self._reported_signatures.add(signature)
            self.vulnerabilities.append(vulnerability)

            print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
            for key, value in vulnerability.items():
                print(f"{key}: {value}")
            print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = webVulScanner(target_url)
    vulnerabilities = scanner.scan()

    # Print summary
    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

