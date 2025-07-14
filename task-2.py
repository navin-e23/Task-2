import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import argparse
import time

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        """
        Initialize the scanner with a target URL.
        
        Args:
            target_url (str): The URL of the web application to scan
        """
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebVulnerabilityScanner/1.0'
        })
        self.vulnerabilities = []
        self.scanned_links = set()
        self.discovered_forms = []

    def scan(self, max_pages=10):
        """
        Perform a comprehensive vulnerability scan.
        
        Args:
            max_pages (int): Maximum number of pages to scan
        """
        print(f"[*] Starting scan of {self.target_url}")
        
        # Start with the target URL
        self.crawl_and_scan(self.target_url, max_pages)
        
        # Test discovered forms for vulnerabilities
        for form in self.discovered_forms:
            self.test_form_for_vulnerabilities(form)
        
        # Print summary of findings
        self.report_findings()

    def crawl_and_scan(self, url, max_pages, current_depth=0, max_depth=2):
        """
        Recursively crawl and scan pages for vulnerabilities.
        
        Args:
            url (str): URL to scan
            max_pages (int): Maximum number of pages to scan
            current_depth (int): Current recursion depth
            max_depth (int): Maximum recursion depth
        """
        if len(self.scanned_links) >= max_pages or current_depth > max_depth:
            return
            
        if url in self.scanned_links:
            return
            
        self.scanned_links.add(url)
        print(f"[*] Scanning: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for XSS in URL parameters
            self.test_reflected_xss(url)
            
            # Check for SQLi in URL parameters
            self.test_reflected_sqli(url)
            
            # Parse the page for forms and links
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Discover and store forms
            forms = soup.find_all('form')
            for form in forms:
                form_details = self.parse_form(form, url)
                self.discovered_forms.append(form_details)
            
            # Discover links and crawl them
            if current_depth < max_depth:
                links = soup.find_all('a', href=True)
                for link in links['href']:
                    absolute_url = urljoin(url, link['href'])
                    if self.target_url in absolute_url and absolute_url not in self.scanned_links:
                        time.sleep(1)  # Be polite with requests
                        self.crawl_and_scan(absolute_url, max_pages, current_depth + 1, max_depth)
                        
        except requests.RequestException as e:
            print(f"[!] Error scanning {url}: {e}")

    def parse_form(self, form, page_url):
        """
        Extract details from an HTML form.
        
        Args:
            form (bs4.element.Tag): The form element
            page_url (str): URL of the page containing the form
            
        Returns:
            dict: Form details including action, method, and inputs
        """
        form_details = {
            'action': urljoin(page_url, form.attrs.get('action', '')),
            'method': form.attrs.get('method', 'get').lower(),
            'inputs': [],
            'page_url': page_url
        }
        
        for input_tag in form.find_all('input'):
            input_details = {
                'type': input_tag.attrs.get('type', 'text'),
                'name': input_tag.attrs.get('name'),
                'value': input_tag.attrs.get('value', '')
            }
            form_details['inputs'].append(input_details)
            
        return form_details

    def test_form_for_vulnerabilities(self, form):
        """
        Test a form for various vulnerabilities.
        
        Args:
            form (dict): Form details from parse_form
        """
        print(f"[*] Testing form at {form['action']}")
        
        # Test for SQL injection
        self.test_sqli_form(form)
        
        # Test for XSS
        self.test_xss_form(form)
        
        # Test for CSRF (lack of token)
        self.test_csrf(form)

    def test_reflected_xss(self, url):
        """
        Test URL parameters for reflected XSS vulnerabilities.
        
        Args:
            url (str): URL to test
        """
        # Extract parameters from URL
        if '?' not in url:
            return
            
        base_url, params = url.split('?', 1)
        param_pairs = params.split('&')
        
        for pair in param_pairs:
            if '=' in pair:
                param_name, param_value = pair.split('=', 1)
                
                # Test with simple XSS payload
                xss_payload = "<script>alert('XSS')</script>"
                modified_url = url.replace(f"{param_name}={param_value}", f"{param_name}={xss_payload}")
                
                try:
                    response = self.session.get(modified_url, timeout=5)
                    if xss_payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'url': modified_url,
                            'parameter': param_name,
                            'payload': xss_payload,
                            'severity': 'High'
                        })
                except requests.RequestException:
                    continue

    def test_reflected_sqli(self, url):
        """
        Test URL parameters for reflected SQL injection vulnerabilities.
        
        Args:
            url (str): URL to test
        """
        if '?' not in url:
            return
            
        base_url, params = url.split('?', 1)
        param_pairs = params.split('&')
        
        for pair in param_pairs:
            if '=' in pair:
                param_name, param_value = pair.split('=', 1)
                
                # Test with simple SQLi payload
                sqli_payload = "' OR '1'='1"
                modified_url = url.replace(f"{param_name}={param_value}", f"{param_name}={sqli_payload}")
                
                try:
                    response = self.session.get(modified_url, timeout=5)
                    if "error in your SQL syntax" in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Reflected SQL Injection',
                            'url': modified_url,
                            'parameter': param_name,
                            'payload': sqli_payload,
                            'severity': 'Critical'
                        })
                except requests.RequestException:
                    continue

    def test_sqli_form(self, form):
        """
        Test a form for SQL injection vulnerabilities.
        
        Args:
            form (dict): Form details from parse_form
        """
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' UNION SELECT null, version()--"
        ]
        
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] == 'hidden':
                data[input_field['name']] = input_field['value']
            else:
                data[input_field['name']] = 'test'
        
        for payload in sqli_payloads:
            test_data = data.copy()
            for input_field in form['inputs']:
                if input_field['type'] not in ['hidden', 'submit']:
                    test_data[input_field['name']] = payload
            
            try:
                if form['method'] == 'post':
                    response = self.session.post(form['action'], data=test_data, timeout=5)
                else:
                    response = self.session.get(form['action'], params=test_data, timeout=5)
                
                error_messages = [
                    'sql syntax',
                    'mysql_fetch',
                    'unclosed quotation mark',
                    'syntax error',
                    'odbc driver',
                    'ora-'
                ]
                
                if any(error in response.text.lower() for error in error_messages):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'form_action': form['action'],
                        'method': form['method'],
                        'payload': payload,
                        'severity': 'Critical',
                        'page_url': form['page_url']
                    })
                    break
                    
            except requests.RequestException:
                continue

    def test_xss_form(self, form):
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            form (dict): Form details from parse_form
        """
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg/onload=alert('XSS')>"
        ]
        
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] == 'hidden':
                data[input_field['name']] = input_field['value']
            else:
                data[input_field['name']] = 'test'
        
        for payload in xss_payloads:
            test_data = data.copy()
            for input_field in form['inputs']:
                if input_field['type'] not in ['hidden', 'submit']:
                    test_data[input_field['name']] = payload
            
            try:
                if form['method'] == 'post':
                    response = self.session.post(form['action'], data=test_data, timeout=5)
                else:
                    response = self.session.get(form['action'], params=test_data, timeout=5)
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'form_action': form['action'],
                        'method': form['method'],
                        'payload': payload,
                        'severity': 'High',
                        'page_url': form['page_url']
                    })
                    break
                    
            except requests.RequestException:
                continue

    def test_csrf(self, form):
        """
        Check if a form is missing CSRF protection.
        
        Args:
            form (dict): Form details from parse_form
        """
        has_csrf_token = False
        for input_field in form['inputs']:
            if input_field['name'] in ['csrf_token', 'csrfmiddlewaretoken', 'authenticity_token']:
                has_csrf_token = True
                break
                
        if not has_csrf_token and form['method'] == 'post':
            self.vulnerabilities.append({
                'type': 'Potential CSRF (Missing Token)',
                'form_action': form['action'],
                'method': form['method'],
                'severity': 'Medium',
                'page_url': form['page_url']
            })

    def report_findings(self):
        """
        Print a summary of discovered vulnerabilities.
        """
        print("\n=== Scan Results ===")
        print(f"Scanned {len(self.scanned_links)} pages")
        print(f"Discovered {len(self.discovered_forms)} forms")
        print(f"Found {len(self.vulnerabilities)} potential vulnerabilities\n")
        
        for vuln in self.vulnerabilities:
            print(f"[{vuln['severity'].upper()}] {vuln['type']}")
            if 'form_action' in vuln:
                print(f"Form: {vuln['form_action']} ({vuln['method'].upper()})")
            if 'url' in vuln:
                print(f"URL: {vuln['url']}")
            if 'parameter' in vuln:
                print(f"Parameter: {vuln['parameter']}")
            if 'payload' in vuln:
                print(f"Payload: {vuln['payload']}")
            print(f"Page: {vuln.get('page_url', 'N/A')}")
            print()

def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-m", "--max-pages", type=int, default=10,
                       help="Maximum number of pages to scan (default: 10)")
    
    args = parser.parse_args()
    
    scanner = WebVulnerabilityScanner(args.url)
    scanner.scan(args.max_pages)

if __name__ == "__main__":
    main()