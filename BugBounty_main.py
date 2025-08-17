#!/usr/bin/env python3
"""
BugBountyScout v2 (hardened)
Compatibilità: Windows/Linux/macOS, Python 3.9+
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import sys
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Tuple

import requests
from bs4 import BeautifulSoup

try:
    from colorama import init as color_init
except Exception:
    def color_init(**kwargs):
        return None

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

# opzionale: cifratura del report
try:
    from cryptography.fernet import Fernet

    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

from logging.handlers import RotatingFileHandler
from urllib3.util import Retry
from requests.adapters import HTTPAdapter


USER_AGENT = os.getenv(
    "BUGBOUNTYSCOUT_USER_AGENT",
    "BugBountyScout/2.1 (+https://github.com/5KBb/BugBountyScout)",
)
HTTP_TIMEOUT = float(os.getenv("BUGBOUNTYSCOUT_TIMEOUT", "10"))
MAX_WORKERS = int(os.getenv("BUGBOUNTYSCOUT_THREADS", "5"))
EXPAND_LINKS = os.getenv("BUGBOUNTYSCOUT_EXPAND_LINKS", "0") == "1"
REPORT_REDACT_BODY = os.getenv("BUGBOUNTYSCOUT_REDACT_BODY", "1") == "1"

SECURITY_HEADERS = (
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
)


# logging sicuro
color_init(autoreset=True)
logger = logging.getLogger("BugBountyScout")
logger.setLevel(logging.INFO)
os.makedirs("logs", exist_ok=True)
_fh = RotatingFileHandler("logs/bugbountyscout.log", maxBytes=1024 * 1024, backupCount=3)
_fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_fh)
logger.addHandler(logging.StreamHandler())

console = Console()


def _redact(s: str, limit: int = 512) -> str:
    """Riduce il rischio di loggare PII/HTML lunghi."""
    s = s or ""
    if len(s) > limit:
        return s[:limit] + "...[snip]"
    return s


def normalize_target(target: str) -> Tuple[str, str]:
    """Normalizza target in URL https://host e host puro."""
    target = target.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        target_url = f"https://{target}"
    else:
        target_url = target
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.hostname:
        raise ValueError(f"Target non valido: {target!r}")
    # forza netloc con host[:port]
    netloc = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{parsed.port}"
    norm = parsed._replace(scheme=parsed.scheme or "https", netloc=netloc, path="/" if not parsed.path else parsed.path)
    return (urllib.parse.urlunparse(norm), parsed.hostname)


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    recommendation: str
    evidence: Dict[str, str]
    component: str


class BugBountyScout:
    def __init__(
        self,
        target: str,
        output_dir: str = "./reports",
        threads: int = MAX_WORKERS,
        verbose: bool = False,
        encrypt_report: bool = False,
        key: Optional[str] = None,
    ):
        self.target_raw = target
        self.base_url, self.hostname = normalize_target(target)
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.threads = max(1, threads)
        self.verbose = verbose
        self.encrypt_report = encrypt_report
        self.key = key
        self.session = build_session()
        self.findings: List[Finding] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None

    # ------------ HTTP helpers ------------
    def _get(self, url: str) -> requests.Response:
        return self.session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)

    # ------------ Scan orchestrator ------------
    def start_scan(self) -> None:
        self.scan_start_time = datetime.now()
        console.print(
            Panel.fit(
                f"[bold green]BugBountyScout v2.1[/bold green]\nTarget: [bold]{self.base_url}[/bold]",
                title="Scan Started",
            )
        )

        urls = self.enumerate_endpoints()
        with Progress() as progress:
            header_task = progress.add_task("[green]Checking HTTP headers...", total=len(urls))
            ssl_task = progress.add_task("[blue]Analyzing SSL/TLS...", total=1)
            xss_task = progress.add_task("[yellow]Scanning for XSS...", total=len(urls))
            sqli_task = progress.add_task("[red]Testing SQLi...", total=len(urls))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                # Headers
                futures = [ex.submit(self.check_http_headers, u) for u in urls]
                for _ in concurrent.futures.as_completed(futures):
                    progress.advance(header_task)

                # SSL
                self.check_ssl_tls()
                progress.advance(ssl_task)

                # XSS
                futures = [ex.submit(self.check_xss_vulnerabilities, u) for u in urls]
                for _ in concurrent.futures.as_completed(futures):
                    progress.advance(xss_task)

                # SQLi
                futures = [ex.submit(self.check_sql_injection, u) for u in urls]
                for _ in concurrent.futures.as_completed(futures):
                    progress.advance(sqli_task)

        self.generate_report()
        self.scan_end_time = datetime.now()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        console.print(
            Panel.fit(
                f"[bold green]Scan completed in {duration:.2f}s[/bold green]\n"
                f"Findings: [bold red]{len(self.findings)}[/bold red]\n"
                f"Report: [bold]{self.output_dir}[/bold]",
                title="Scan Completed",
            )
        )

    # ------------ Enumerazione ------------
    def enumerate_endpoints(self) -> List[str]:
        """Per default: solo la home del dominio; opzionale: crawl superficiale (stesso host, max 30)."""
        urls = {self.base_url.rstrip("/")}
        if EXPAND_LINKS:
            try:
                r = self._get(self.base_url)
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urllib.parse.urljoin(self.base_url, a["href"])
                    p = urllib.parse.urlparse(href)
                    if p.hostname == self.hostname:
                        urls.add(urllib.parse.urlunparse(p._replace(fragment="")))
                        if len(urls) >= 30:
                            break
            except Exception as e:
                logger.warning("Enumerazione ridotta: %s", e)
        return sorted(urls)

    # ------------ Checks ------------
    def check_http_headers(self, url: str) -> None:
        try:
            r = self._get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            missing = []
            for h in SECURITY_HEADERS:
                if h == "strict-transport-security" and not url.lower().startswith("https://"):
                    continue
                if h not in headers:
                    missing.append(h)
            if missing:
                self.findings.append(
                    Finding(
                        title="Missing security headers",
                        severity="Medium",
                        description=f"Headers mancanti: {', '.join(missing)}",
                        recommendation="Impostare header di sicurezza raccomandati (CSP, X-CTO, XFO, HSTS, Referrer-Policy, Permissions-Policy).",
                        evidence={"url": url, "missing": ", ".join(missing)},
                        component="http_headers",
                    )
                )
        except Exception as e:
            logger.error("Header check error %s: %s", url, e)

    def check_ssl_tls(self) -> None:
        """Controllo certificato e handshake minimo."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=HTTP_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.utcnow()).days
                        if days < 0:
                            self.findings.append(
                                Finding(
                                    title="Expired TLS certificate",
                                    severity="High",
                                    description=f"Certificato scaduto da {-days} giorni",
                                    recommendation="Rinnovare il certificato e abilitare auto-renew.",
                                    evidence={"host": self.hostname, "notAfter": not_after},
                                    component="tls",
                                )
                            )
                        elif days < 30:
                            self.findings.append(
                                Finding(
                                    title="TLS certificate close to expiry",
                                    severity="Low",
                                    description=f"Certificato in scadenza in {days} giorni",
                                    recommendation="Pianificare il rinnovo (<30 giorni).",
                                    evidence={"host": self.hostname, "notAfter": not_after},
                                    component="tls",
                                )
                            )
        except Exception as e:
            self.findings.append(
                Finding(
                    title="TLS handshake/validation issue",
                    severity="Medium",
                    description="Errore durante handshake TLS o recupero certificato.",
                    recommendation="Verificare catena certificati, SNI, porte e policy TLS.",
                    evidence={"host": self.hostname, "error": str(e)},
                    component="tls",
                )
            )

    def check_xss_vulnerabilities(self, url: str) -> None:
        payloads = [
            "<script>alert(1)</script>",
            "\"><svg onload=alert(1)>",
        ]
        try:
            p = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qs(p.query)
            key = list(q.keys())[0] if q else "q"
            for pay in payloads:
                new_q = q.copy()
                new_q[key] = [pay]
                new_url = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(new_q, doseq=True)))
                r = self._get(new_url)
                body = r.text
                if pay in body:
                    self.findings.append(
                        Finding(
                            title="Reflected XSS (possible)",
                            severity="High",
                            description="Payload riflesso nella risposta.",
                            recommendation="Evadere/filtrare output, CSP restrittivo, validazione input.",
                            evidence={"url": new_url, "reflected": _redact(pay)},
                            component="xss",
                        )
                    )
                    break
        except Exception as e:
            logger.error("XSS check error %s: %s", url, e)

    def check_sql_injection(self, url: str) -> None:
        payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "';WAITFOR DELAY '0:0:1'--"]
        sql_errors = re.compile(
            r"(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|UNEXPECTED '|' near|SQLite/JDBC|PG::SyntaxError)",
            re.I,
        )
        try:
            p = urllib.parse.urlparse(url)
            q = urllib.parse.parse_qs(p.query)
            key = list(q.keys())[0] if q else "id"
            for pay in payloads:
                new_q = q.copy()
                new_q[key] = [pay]
                new_url = urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(new_q, doseq=True)))
                r = self._get(new_url)
                if sql_errors.search(r.text or ""):
                    self.findings.append(
                        Finding(
                            title="SQL Injection (error-based, possible)",
                            severity="High",
                            description="Pattern di errore DB individuato nella risposta.",
                            recommendation="Usare query parametrizzate e WAF; validare input.",
                            evidence={"url": new_url, "indicator": "db-error"},
                            component="sqli",
                        )
                    )
                    break
        except Exception as e:
            logger.error("SQLi check error %s: %s", url, e)

    # ------------ Report ------------
    def generate_report(self) -> None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = {
            "meta": {
                "target": self.base_url,
                "started": self.scan_start_time.isoformat() if self.scan_start_time else None,
                "finished": self.scan_end_time.isoformat() if self.scan_end_time else None,
                "version": "2.1",
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": {
                    "High": sum(1 for f in self.findings if f.severity == "High"),
                    "Medium": sum(1 for f in self.findings if f.severity == "Medium"),
                    "Low": sum(1 for f in self.findings if f.severity == "Low"),
                },
            },
            "findings": [asdict(f) for f in self.findings],
        }
        path = os.path.join(self.output_dir, f"report_{ts}.json")
        raw = json.dumps(out, ensure_ascii=False, indent=2)
        if self.encrypt_report and HAS_CRYPTO and self.key:
            try:
                f = Fernet(self.key.encode())
                enc = f.encrypt(raw.encode("utf-8"))
                with open(path + ".enc", "wb") as w:
                    w.write(enc)
                return
            except Exception as e:
                logger.error("Cifratura report fallita: %s", e)
        with open(path, "w", encoding="utf-8") as w:
            w.write(raw)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="bugbountyscout",
        description="BugBountyScout - Automated checks for headers, TLS, XSS, SQLi",
    )
    p.add_argument("target", help="Target URL o dominio (es. example.com)")
    p.add_argument("-o", "--output", default="./reports", help="Directory report (default: ./reports)")
    p.add_argument("-t", "--threads", type=int, default=MAX_WORKERS, help=f"Thread (default: {MAX_WORKERS})")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    p.add_argument("--encrypt-report", action="store_true", help="Cifra il report con Fernet")
    p.add_argument("--key", help="Chiave Fernet (base64 urlsafe)")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = _parse_args(argv)
    try:
        scanner = BugBountyScout(
            target=ns.target,
            output_dir=ns.output,
            threads=ns.threads,
            verbose=ns.verbose,
            encrypt_report=ns.encrypt_report,
            key=ns.key,
        )
        scanner.start_scan()
        return 0
    except Exception as e:
        logger.error("Fatal: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
