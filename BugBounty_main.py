#!/usr/bin/env python3
# BugBountyScout v2 - Ethical Hacking Edition
# Author: 5KBb + ChatGPT Security Review
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

try:
    from cryptography.fernet import Fernet  # Optional for report encryption
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Set up logging with rotation
from logging.handlers import RotatingFileHandler
log_file = "bugbountyscout.log"
logger = logging.getLogger("BugBountyScout")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=3)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(logging.StreamHandler())

# Rich console for better terminal output
console = Console()

class BugBountyScout:
    def __init__(self, target, output_dir="./reports", threads=5, verbose=False, encrypt_report=False, key=None):
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.verbose = verbose
        self.encrypt_report = encrypt_report
        self.key = key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyScout/2.0 (https://github.com/5KBb/BugBountyScout)'
        })
        self.findings = []
        self.scan_start_time = None
        self.scan_end_time = None
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        if not os.path.exists("logs"):
            os.makedirs("logs")

    def start_scan(self):
        self.scan_start_time = datetime.now()
        console.print(Panel.fit(
            f"[bold green]BugBountyScout v2.0[/bold green]\n"
            f"Starting scan on target: [bold]{self.target}[/bold]",
            title="Scan Started"
        ))

        urls = self.enumerate_endpoints()
        with Progress() as progress:
            header_task = progress.add_task("[green]Checking HTTP headers...", total=len(urls))
            ssl_task = progress.add_task("[blue]Analyzing SSL/TLS...", total=1)
            xss_task = progress.add_task("[yellow]Scanning for XSS...", total=len(urls))
            sqli_task = progress.add_task("[red]Testing SQLi...", total=len(urls))

            # Multithreaded scans
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # HTTP Header scan
                futures = [executor.submit(self.check_http_headers, url, progress, header_task) for url in urls]
                concurrent.futures.wait(futures)

                # SSL scan (solo su dominio principale)
                self.check_ssl_tls(progress, ssl_task)

                # XSS scan
                futures = [executor.submit(self.check_xss_vulnerabilities, url, progress, xss_task) for url in urls]
                concurrent.futures.wait(futures)

                # SQLi scan
                futures = [executor.submit(self.check_sql_injection, url, progress, sqli_task) for url in urls]
                concurrent.futures.wait(futures)

        self.generate_report()
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        console.print(Panel.fit(
            f"[bold green]Scan completed in {duration:.2f} seconds[/bold green]\n"
            f"Found [bold red]{len(self.findings)}[/bold red] potential vulnerabilities\n"
            f"Full report saved to: [bold]{self.output_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json[/bold]" +
            ("\n[bold yellow]WARNING: Report contains potentially sensitive data.[/bold yellow]" if self.encrypt_report else ""),
            title="Scan Completed"
        ))

    def enumerate_endpoints(self):
        """Espandibile: per ora scansiona solo l'URL principale. 
        In futuro: aggiungi recon automatico di endpoints/subdomini."""
        return [self.normalize_url(self.target)]

    def normalize_url(self, url):
        """Tenta HTTPS, fallback a HTTP se fallisce"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        try:
            resp = self.session.get(url, timeout=5)
            return url
        except Exception:
            # fallback HTTP
            url = url.replace("https://", "http://")
            try:
                self.session.get(url, timeout=5)
                logger.warning("Downgraded to HTTP due to connection failure.")
                return url
            except Exception as e:
                logger.error(f"Target {url} not reachable: {e}")
                raise
        return url

    def check_http_headers(self, url, progress, task_id):
        progress.update(task_id, advance=1)
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            # Security headers
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
                        description=f"{header} is missing in the response.",
                        recommendation=f"Add {header} header.",
                        evidence=f"URL: {url} - Status: {response.status_code}"
                    )
            # Info disclosure
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in sensitive_headers:
                if header in response.headers:
                    self.add_finding(
                        title=f"Information disclosure: {header}",
                        severity="Low",
                        description=f"{header} reveals technology info: {response.headers[header]}",
                        recommendation=f"Remove or obfuscate {header} header.",
                        evidence=f"{header}: {response.headers[header]}"
                    )
            # Cookie flags (Set-Cookie header parsing)
            set_cookies = response.headers.get('Set-Cookie', '')
            for cookie_str in set_cookies.split(','):
                name = cookie_str.split('=')[0].strip()
                if 'secure' not in cookie_str.lower():
                    self.add_finding(
                        title="Cookie missing Secure flag",
                        severity="Medium",
                        description=f"Cookie '{name}' sent without Secure flag.",
                        recommendation="Add Secure flag to all cookies.",
                        evidence=cookie_str
                    )
                if 'httponly' not in cookie_str.lower():
                    self.add_finding(
                        title="Cookie missing HttpOnly flag",
                        severity="Medium",
                        description=f"Cookie '{name}' sent without HttpOnly flag.",
                        recommendation="Add HttpOnly flag to all cookies.",
                        evidence=cookie_str
                    )
        except Exception as e:
            self.add_finding(
                title="Error connecting to target",
                severity="Info",
                description=f"Could not connect to {url}: {str(e)}",
                recommendation="Verify the target URL is correct.",
                evidence=str(e)
            )

    def check_ssl_tls(self, progress, task_id):
        progress.update(task_id, completed=1)
        parsed_url = urllib.parse.urlparse(self.normalize_url(self.target))
        hostname = parsed_url.netloc.split(':')[0]
        try:
            context = ssl.create_default_context()
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disabilita vecchi protocolli
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    if 'notAfter' in cert:
                        expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        days_left = (expiry_date - current_time) / (24 * 3600)
                        if days_left < 0:
                            self.add_finding(
                                title="SSL Certificate Expired",
                                severity="High",
                                description=f"SSL certificate expired.",
                                recommendation="Renew certificate.",
                                evidence=f"Expired on: {cert['notAfter']}"
                            )
                        elif days_left < 30:
                            self.add_finding(
                                title="SSL Certificate Expiring Soon",
                                severity="Medium",
                                description=f"SSL cert expires in {int(days_left)} days.",
                                recommendation="Renew certificate soon.",
                                evidence=f"Expires on: {cert['notAfter']}"
                            )
                    if cipher[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5']:
                        self.add_finding(
                            title="Weak Cipher Suite",
                            severity="High",
                            description=f"Weak cipher in use: {cipher[0]}",
                            recommendation="Disable weak ciphers.",
                            evidence=f"Cipher: {cipher[0]}"
                        )
        except Exception as e:
            self.add_finding(
                title="SSL/TLS Verification Failed",
                severity="Info",
                description=f"SSL/TLS scan failed for {hostname}: {str(e)}",
                recommendation="Ensure target supports HTTPS and is accessible.",
                evidence=str(e)
            )

    def check_xss_vulnerabilities(self, url, progress, task_id):
        progress.update(task_id, advance=1)
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            test_payloads = [
                "<script>alert(1)</script>",
                "\"><svg/onload=alert(1337)>",
                "';alert(1);//",
                "BugBountyScoutXSSTest"
            ]
            # Test all forms
            for form in forms:
                form_url = urllib.parse.urljoin(url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                all_fields = [f for f in form.find_all(['input', 'textarea', 'select']) if f.get('name')]
                # CSRF detection
                csrf_tokens = [f for f in all_fields if 'csrf' in f.get('name', '').lower()]
                form_data = {}
                for field in all_fields:
                    for payload in test_payloads:
                        form_data = {f.get('name'): (payload if f == field else f.get('value', '')) for f in all_fields}
                        if method == 'post':
                            resp = self.session.post(form_url, data=form_data, timeout=10)
                        else:
                            resp = self.session.get(form_url, params=form_data, timeout=10)
                        if any(payload in resp.text for payload in test_payloads):
                            self.add_finding(
                                title="Reflected XSS",
                                severity="High",
                                description=f"Reflected XSS found in '{field.get('name')}' via {method.upper()}",
                                recommendation="Sanitize and encode all user input.",
                                evidence=f"Payload: {payload}\nField: {field.get('name')}"
                            )
            # DOM XSS
            dom_xss_sinks = ['document.write', 'innerHTML', 'outerHTML', 'eval(', 'setTimeout(', 'setInterval(']
            scripts = soup.find_all('script')
            for script in scripts:
                code = script.string or ""
                for sink in dom_xss_sinks:
                    if sink in code:
                        self.add_finding(
                            title="Potential DOM-based XSS",
                            severity="Medium",
                            description=f"Unsafe JS sink: {sink} detected.",
                            recommendation="Sanitize all JS input; review DOM operations.",
                            evidence=f"JS sink: {sink} in {url}"
                        )
        except Exception as e:
            logger.warning(f"XSS scan failed: {str(e)}")
            if self.verbose:
                self.add_finding(
                    title="XSS scan error",
                    severity="Info",
                    description=str(e),
                    recommendation="Review error trace.",
                    evidence="XSS scan stack trace"
                )

    def check_sql_injection(self, url, progress, task_id):
        progress.update(task_id, advance=1)
        try:
            payloads = [
                "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "admin' --",
                "'; WAITFOR DELAY '0:0:5'--",  # Time-based
                "1) OR SLEEP(5)--+"
            ]
            sql_errors = [
                "SQL syntax", "mysql_fetch", "mysqli_", "Warning: mysql",
                "ODBC Driver", "SQLServer", "PostgreSQL ERROR", "SQLite Error", "syntax error"
            ]
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            # Test all forms
            for form in forms:
                form_url = urllib.parse.urljoin(url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                all_fields = [f for f in form.find_all(['input', 'textarea', 'select']) if f.get('name')]
                for field in all_fields:
                    for payload in payloads:
                        form_data = {f.get('name'): (payload if f == field else f.get('value', '')) for f in all_fields}
                        try:
                            if method == 'post':
                                resp = self.session.post(form_url, data=form_data, timeout=10)
                            else:
                                resp = self.session.get(form_url, params=form_data, timeout=10)
                            for err in sql_errors:
                                if err in resp.text:
                                    self.add_finding(
                                        title="SQL Injection",
                                        severity="Critical",
                                        description=f"Form param '{field.get('name')}' likely vulnerable (error-based)",
                                        recommendation="Use parameterized queries, validate input.",
                                        evidence=f"Payload: {payload}\nError: {err}\nForm: {form_url}"
                                    )
                        except Exception as ex:
                            continue
            # URL parameters
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in payloads:
                    new_params = params.copy()
                    new_params[param] = payload
                    test_url = parsed_url._replace(query=urllib.parse.urlencode(new_params, doseq=True)).geturl()
                    try:
                        resp = self.session.get(test_url, timeout=10)
                        for err in sql_errors:
                            if err in resp.text:
                                self.add_finding(
                                    title="SQL Injection",
                                    severity="Critical",
                                    description=f"GET param '{param}' likely vulnerable.",
                                    recommendation="Use parameterized queries, validate input.",
                                    evidence=f"Payload: {payload}\nError: {err}\nURL: {test_url}"
                                )
                        # Simple time-based (delay > 4s)
                        if resp.elapsed.total_seconds() > 4:
                            self.add_finding(
                                title="Time-based SQLi",
                                severity="High",
                                description=f"Response delayed ({resp.elapsed.total_seconds()}s), potential time-based SQLi.",
                                recommendation="Use parameterized queries.",
                                evidence=f"Payload: {payload}\nURL: {test_url}"
                            )
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"SQLi scan failed: {str(e)}")
            if self.verbose:
                self.add_finding(
                    title="SQLi scan error",
                    severity="Info",
                    description=str(e),
                    recommendation="Review error trace.",
                    evidence="SQLi scan stack trace"
                )

    def add_finding(self, title, severity, description, recommendation, evidence):
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
            logger.info(f"{severity}: {title} | {description}")

    def generate_report(self):
        report = {
            "scan_info": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "scan_duration": (datetime.now() - self.scan_start_time).total_seconds() if self.scan_start_time else 0,
                "tool_version": "2.0"
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
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        # Encrypt if needed
        if self.encrypt_report and HAS_CRYPTO and self.key:
            f = Fernet(self.key)
            enc = f.encrypt(json.dumps(report, indent=4).encode())
            with open(filepath + ".enc", 'wb') as f_enc:
                f_enc.write(enc)
            console.print(f"\n[bold green]Encrypted report saved to: {filepath}.enc[/bold green]")
        else:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=4)
            console.print(f"\n[bold green]Report saved to: {filepath}[/bold green]")
        # Print summary
        table = Table(title="Findings Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count")
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            table.add_row(severity, str(report["summary"]["by_severity"][severity]))
        console.print("\n", table)
        if not self.encrypt_report:
            console.print("\n[bold yellow]WARNING: The report may contain sensitive data![/bold yellow]")

def main():
    parser = argparse.ArgumentParser(
        description="BugBountyScout v2 - Ethical Hacking Edition",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Target URL or domain to scan")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory for reports")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--encrypt-report", action="store_true", help="Encrypt report with Fernet key")
    parser.add_argument("--key", default=None, help="Fernet key for report encryption (optional)")
    args = parser.parse_args()

    if args.encrypt_report and (not HAS_CRYPTO or not args.key):
        console.print("[bold red]cryptography module not available or no key provided![/bold red]")
        sys.exit(1)

    try:
        scanner = BugBountyScout(
            target=args.target,
            output_dir=args.output,
            threads=args.threads,
            verbose=args.verbose,
            encrypt_report=args.encrypt_report,
            key=args.key.encode() if args.key else None
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


