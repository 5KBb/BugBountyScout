import requests
import requests_mock
from BugBounty_main import BugBountyScout, normalize_target


def test_normalize_target_adds_scheme():
    url, host = normalize_target("example.com")
    assert url.startswith("https://")
    assert host == "example.com"


def test_headers_missing_marked():
    s = BugBountyScout("https://example.com")
    with requests_mock.Mocker() as m:
        m.get("https://example.com/", headers={"Server": "nginx"}, text="<html/>")
        s.check_http_headers("https://example.com/")
    assert any(f.component == "http_headers" for f in s.findings)


def test_xss_reflection_detected():
    s = BugBountyScout("https://example.com")
    with requests_mock.Mocker() as m:
        m.get("https://example.com/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", text="<p><script>alert(1)</script></p>")
        s.check_xss_vulnerabilities("https://example.com/")
    assert any(f.component == "xss" for f in s.findings)


def test_sqli_error_based():
    s = BugBountyScout("https://example.com")
    with requests_mock.Mocker() as m:
        m.get(requests_mock.ANY, text="You have an error in your SQL syntax; check the manual...")
        s.check_sql_injection("https://example.com/")
    assert any(f.component == "sqli" for f in s.findings)
