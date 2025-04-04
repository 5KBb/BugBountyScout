#!/usr/bin/env python3
# BugBountyScout - An automated tool for security researchers and bug bounty hunters
# Author: 5KBb
# License: MIT

import argparse
import sys
import os
import json
import time
import logging
import requests
import socket
import ssl
import concurrent.futures
import ipaddress
import re
import urllib.parse
from datetime import datetime
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbountyscout.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("BugBountyScout")

# Rich console for better terminal output
console = Console()

class BugBountyScout:
    def __init__(self, target, output_dir="./reports", threads=5, verbose=False):
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyScout/1.0 (https://github.com/yourusername/BugBountyScout)'
        })
        self.findings = []
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Ensure output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def start_scan(self):
        """Main method to start the security scan"""
        self.scan_start_time = datetime.now()
        console.print(Panel.fit(
            f"[bold green]BugBountyScout v1.0[/bold green]\n"
            f"Starting scan on target: [bold]{self.target}[/bold]",
            title="Scan Started"
        ))
        
        # Run all scanners
        with Progress() as progress:
            # Add tasks to progress bar
            header_task = progress.add_task("[green]Checking HTTP headers...", total=1)
            ssl_task = progress.add_task("[blue]Analyzing SSL/TLS...", total=1)
            xss_task = progress.add_task("[yellow]Scanning for XSS vulnerabilities...", total=1)
            sqli_task = progress.add_task("[red]Testing SQL injection points...", total=1)
            
            # Check HTTP headers
            self.check_http_headers(progress, header_task)
            
            # Check SSL/TLS configuration
            self.check_ssl_tls(progress, ssl_task)
            
            # Check for XSS vulnerabilities
            self.check_xss_vulnerabilities(progress, xss_task)
            
            # Check for SQL injection
            self.check_sql_injection(progress, sqli_task)
        
        # Generate report
        self.generate_report()
        
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        console.print(Panel.fit(
            f"[bold green]Scan completed in {duration:.2f} seconds[/bold green]\n"
            f"Found [bold red]{len(self.findings)}[/bold red] potential vulnerabilities\n"
            f"Full report saved to: [bold]{self.output_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json[/bold]",
            title="Scan Completed"
        ))
    
    def check_http_headers(self, progress, task_id):
        """Check for security headers and misconfigurations"""
        progress.update(task_id, description="[green]Checking HTTP headers...", completed=0.2)
        
        try:
            url = self.normalize_url(self.target)
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Security headers to check for
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing or outdated XSS protection header'
            }
            
            for header, issue in security_headers.items():
                if header not in response.headers:
                    self.add_finding(
                        title=issue,
                        severity="Medium",
                        description=f"The {header} security header is missing. This could expose the site to various attacks.",
                        recommendation=f"Implement the {header} header in your HTTP responses.",
                        evidence=f"URL: {url}\nStatus Code: {response.status_code}"
                    )
            
            # Check for information disclosure in headers
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in sensitive_headers:
                if header in response.headers:
                    self.add_finding(
                        title=f"Information disclosure in {header} header",
                        severity="Low",
                        description=f"The {header} header reveals technology information: {response.headers[header]}",
                        recommendation=f"Remove or sanitize the {header} header to prevent information disclosure.",
                        evidence=f"Header value: {header}: {response.headers[header]}"
                    )
            
            # Check for cookies without secure flag
            for cookie in response.cookies:
                if not cookie.secure:
                    self.add_finding(
                        title="Cookie without Secure flag",
                        severity="Medium",
                        description=f"The cookie '{cookie.name}' is set without the Secure flag, allowing transmission over unencrypted connections.",
                        recommendation="Set the Secure flag on all cookies to ensure they are only transmitted over HTTPS.",
                        evidence=f"Cookie: {cookie.name}"
                    )
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self.add_finding(
                        title="Cookie without HttpOnly flag",
                        severity="Medium",
                        description=f"The cookie '{cookie.name}' is set without the HttpOnly flag, making it accessible to JavaScript.",
                        recommendation="Set the HttpOnly flag on all cookies to protect against XSS attacks.",
                        evidence=f"Cookie: {cookie.name}"
                    )
            
            progress.update(task_id, completed=1.0)
            
        except requests.exceptions.RequestException as e:
            self.add_finding(
                title="Error connecting to target",
                severity="Info",
                description=f"Could not connect to {url}: {str(e)}",
                recommendation="Verify the target URL is correct and accessible.",
                evidence=str(e)
            )
            progress.update(task_id, completed=1.0)
    
    def check_ssl_tls(self, progress, task_id):
        """Check SSL/TLS configuration for vulnerabilities"""
        progress.update(task_id, description="[blue]Analyzing SSL/TLS...", completed=0.3)
        
        try:
            # Extract hostname from target
            parsed_url = urllib.parse.urlparse(self.normalize_url(self.target))
            hostname = parsed_url.netloc
            
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # Connect to the server
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        days_left = (expiry_date - current_time) / (24 * 3600)
                        
                        if days_left < 0:
                            self.add_finding(
                                title="SSL Certificate Expired",
                                severity="High",
                                description=f"The SSL certificate for {hostname} has expired.",
                                recommendation="Renew the SSL certificate immediately.",
                                evidence=f"Certificate expired on: {cert['notAfter']}"
                            )
                        elif days_left < 30:
                            self.add_finding(
                                title="SSL Certificate Expiring Soon",
                                severity="Medium",
                                description=f"The SSL certificate for {hostname} will expire in {int(days_left)} days.",
                                recommendation="Plan to renew the SSL certificate soon.",
                                evidence=f"Certificate expires on: {cert['notAfter']}"
                            )
                    
                    # Check weak cipher suites
                    if cipher[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5']:
                        self.add_finding(
                            title="Weak Cipher Suite Detected",
                            severity="High",
                            description=f"The server is using weak cipher suite: {cipher[0]}",
                            recommendation="Configure the server to use strong cipher suites and disable weak ones.",
                            evidence=f"Detected cipher: {cipher[0]}"
                        )
            
            progress.update(task_id, completed=1.0)
            
        except (socket.gaierror, socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            if self.verbose:
                logger.warning(f"SSL/TLS check failed: {str(e)}")
            self.add_finding(
                title="SSL/TLS Verification Failed",
                severity="Info",
                description=f"Could not verify SSL/TLS for {hostname}: {str(e)}",
                recommendation="Ensure the target supports HTTPS and is accessible.",
                evidence=str(e)
            )
            progress.update(task_id, completed=1.0)
    
    def check_xss_vulnerabilities(self, progress, task_id):
        """Check for potential XSS vulnerabilities"""
        progress.update(task_id, description="[yellow]Scanning for XSS vulnerabilities...", completed=0.2)
        
        try:
            url = self.normalize_url(self.target)
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all input fields, forms, and URL parameters
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            
            progress.update(task_id, completed=0.4)
            
            # Check for reflected content
            test_payload = 'BugBountyScoutXSSTest'
            reflected_params = []
            
            # Parse URL parameters if any
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            # Test existing parameters for reflection
            if params:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={test_payload}")
                    test_response = self.session.get(test_url, timeout=10)
                    if test_payload in test_response.text:
                        reflected_params.append(param)
            
            # Test forms for reflection
            for form in forms:
                form_inputs = form.find_all('input')
                if form.get('action'):
                    form_url = urllib.parse.urljoin(url, form.get('action'))
                else:
                    form_url = url
                
                method = form.get('method', 'get').lower()
                
                # Create test data for the form
                form_data = {}
                for input_field in form_inputs:
                    if input_field.get('name'):
                        form_data[input_field.get('name')] = test_payload
                
                # Submit the form
                if method == 'post':
                    test_response = self.session.post(form_url, data=form_data, timeout=10)
                else:
                    test_response = self.session.get(form_url, params=form_data, timeout=10)
                
                # Check if payload is reflected
                if test_payload in test_response.text:
                    for input_name in form_data:
                        reflected_params.append(f"{form_url} - {input_name}")
            
            progress.update(task_id, completed=0.8)
            
            # Report findings for all reflected parameters
            for param in reflected_params:
                self.add_finding(
                    title="Potential Reflected XSS Vulnerability",
                    severity="High",
                    description=f"The parameter/input '{param}' reflects user input in the response without proper encoding.",
                    recommendation="Implement proper input validation and output encoding to prevent XSS attacks.",
                    evidence=f"Parameter: {param}\nTest payload: {test_payload}"
                )
            
            # Check for DOM-based XSS vulnerabilities
            scripts = soup.find_all('script')
            dom_xss_sinks = ['document.write', 'innerHTML', 'outerHTML', 'eval(', 'setTimeout(', 'setInterval(']
            
            for script in scripts:
                if script.string:
                    for sink in dom_xss_sinks:
                        if sink in script.string:
                            self.add_finding(
                                title="Potential DOM-based XSS Vulnerability",
                                severity="High",
                                description=f"The page contains JavaScript that uses the potentially unsafe sink '{sink}'.",
                                recommendation="Review the JavaScript code and ensure user input is properly validated and encoded before use in DOM operations.",
                                evidence=f"JavaScript sink: {sink}\nURL: {url}"
                            )
            
            progress.update(task_id, completed=1.0)
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                logger.warning(f"XSS scan failed: {str(e)}")
            progress.update(task_id, completed=1.0)
    
    def check_sql_injection(self, progress, task_id):
        """Check for potential SQL injection vulnerabilities"""
        progress.update(task_id, description="[red]Testing SQL injection points...", completed=0.2)
        
        try:
            url = self.normalize_url(self.target)
            
            # SQL injection test payloads
            payloads = [
                "' OR '1'='1", 
                "' OR '1'='1' --", 
                "1' OR '1'='1", 
                "1 OR 1=1", 
                "' OR ''='", 
                "' OR 1=1--"
            ]
            
            # Get form details from the page
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            progress.update(task_id, completed=0.4)
            
            # Parse URL parameters if any
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            # Test URL parameters for SQL injection
            vulnerable_params = []
            if params:
                for param in params:
                    for payload in payloads:
                        test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                        try:
                            test_response = self.session.get(test_url, timeout=10)
                            
                            # Look for common SQL error messages
                            sql_errors = [
                                "SQL syntax", "mysql_fetch_array", "mysql_fetch_assoc", 
                                "mysql_num_rows", "mysqli_fetch_array", "mysqli_result",
                                "Warning: mysql", "ORA-", "Oracle Error", "Microsoft SQL",
                                "ODBC Driver", "SQLServer", "PostgreSQL ERROR"
                            ]
                            
                            for error in sql_errors:
                                if error in test_response.text:
                                    vulnerable_params.append((param, payload, error))
                                    break
                            
                        except requests.exceptions.RequestException:
                            continue
            
            progress.update(task_id, completed=0.7)
            
            # Test forms for SQL injection
            for form in forms:
                form_inputs = form.find_all('input')
                if form.get('action'):
                    form_url = urllib.parse.urljoin(url, form.get('action'))
                else:
                    form_url = url
                
                method = form.get('method', 'get').lower()
                
                for input_field in form_inputs:
                    if input_field.get('name'):
                        input_name = input_field.get('name')
                        
                        for payload in payloads:
                            # Create test data for the form
                            form_data = {}
                            for inp in form_inputs:
                                if inp.get('name'):
                                    if inp.get('name') == input_name:
                                        form_data[inp.get('name')] = payload
                                    else:
                                        form_data[inp.get('name')] = inp.get('value', '')
                            
                            # Submit the form
                            try:
                                if method == 'post':
                                    test_response = self.session.post(form_url, data=form_data, timeout=10)
                                else:
                                    test_response = self.session.get(form_url, params=form_data, timeout=10)
                                
                                # Look for common SQL error messages
                                sql_errors = [
                                    "SQL syntax", "mysql_fetch_array", "mysql_fetch_assoc", 
                                    "mysql_num_rows", "mysqli_fetch_array", "mysqli_result",
                                    "Warning: mysql", "ORA-", "Oracle Error", "Microsoft SQL",
                                    "ODBC Driver", "SQLServer", "PostgreSQL ERROR"
                                ]
                                
                                for error in sql_errors:
                                    if error in test_response.text:
                                        vulnerable_params.append((f"{form_url} - {input_name}", payload, error))
                                        break
                                        
                            except requests.exceptions.RequestException:
                                continue
            
            # Report findings for all vulnerable parameters
            for param, payload, error in vulnerable_params:
                self.add_finding(
                    title="Potential SQL Injection Vulnerability",
                    severity="Critical",
                    description=f"The parameter '{param}' appears to be vulnerable to SQL injection attacks.",
                    recommendation="Implement prepared statements or parameterized queries. Validate and sanitize all user inputs.",
                    evidence=f"Parameter: {param}\nPayload: {payload}\nError: {error}"
                )
            
            progress.update(task_id, completed=1.0)
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                logger.warning(f"SQL injection scan failed: {str(e)}")
            progress.update(task_id, completed=1.0)
    
    def add_finding(self, title, severity, description, recommendation, evidence):
        """Add a security finding to the list"""
        finding = {
            "id": len(self.findings) + 1,
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        
        if self.verbose:
            if severity == "Critical":
                color = Fore.RED + Style.BRIGHT
            elif severity == "High":
                color = Fore.RED
            elif severity == "Medium":
                color = Fore.YELLOW
            elif severity == "Low":
                color = Fore.BLUE
            else:
                color = Fore.WHITE
                
            logger.info(f"{color}[{severity}] {title}{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate a detailed report of findings"""
        report = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "scan_duration": (datetime.now() - self.scan_start_time).total_seconds() if self.scan_start_time else 0,
                "tool_version": "1.0"
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": {
                    "Critical": len([f for f in self.findings if f["severity"] == "Critical"]),
                    "High": len([f for f in self.findings if f["severity"] == "High"]),
                    "Medium": len([f for f in self.findings if f["severity"] == "Medium"]),
                    "Low": len([f for f in self.findings if f["severity"] == "Low"]),
                    "Info": len([f for f in self.findings if f["severity"] == "Info"])
                }
            },
            "findings": self.findings
        }
        
        # Create report filename with timestamp
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Write report to file
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Print summary table
        table = Table(title="Findings Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count")
        
        table.add_row("Critical", str(report["summary"]["by_severity"]["Critical"]))
        table.add_row("High", str(report["summary"]["by_severity"]["High"]))
        table.add_row("Medium", str(report["summary"]["by_severity"]["Medium"]))
        table.add_row("Low", str(report["summary"]["by_severity"]["Low"]))
        table.add_row("Info", str(report["summary"]["by_severity"]["Info"]))
        
        console.print("\n")
        console.print(table)
        console.print(f"\nDetailed report saved to: {filepath}")
    
    def normalize_url(self, url):
        """Ensure URL has a scheme"""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url


def main():
    """Main entry point for the command line interface"""
    parser = argparse.ArgumentParser(
        description="BugBountyScout - An automated tool for security researchers and bug bounty hunters",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("target", help="Target URL or domain to scan")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    try:
        scanner = BugBountyScout(
            target=args.target,
            output_dir=args.output,
            threads=args.threads,
            verbose=args.verbose
        )
        
        scanner.start_scan()
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()

