# modules/headers.py
# OrionToolkit - HTTP Header Analysis Module

import requests
from rich.console import Console

console = Console()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"weight": 15, "desc": "HSTS enabled"},
    "Content-Security-Policy": {"weight": 15, "desc": "CSP enabled"},
    "X-Content-Type-Options": {"weight": 10, "desc": "MIME sniffing protection"},
    "X-Frame-Options": {"weight": 10, "desc": "Clickjacking protection"},
    "X-XSS-Protection": {"weight": 5, "desc": "XSS filter enabled"},
    "Referrer-Policy": {"weight": 10, "desc": "Referrer policy set"},
    "Permissions-Policy": {"weight": 10, "desc": "Permissions policy set"},
    "Set-Cookie": {"weight": 5, "desc": "Cookies set — check Secure/HttpOnly flags"},
    "Access-Control-Allow-Origin": {"weight": 5, "desc": "CORS header present"},
}

VULNERABLE_HEADERS = {
    "Server": {"weight": 5, "desc": "Server version disclosure"},
    "X-Powered-By": {"weight": 10, "desc": "Tech stack disclosure"},
    "X-AspNet-Version": {"weight": 10, "desc": "ASP.NET version disclosure"},
}


class HeaderAnalyzer:
    """Analyze HTTP response headers for security and information disclosure."""

    def __init__(self, url: str):
        self.url = url
        self.results = {}

    def analyze(self) -> dict:
        """Fetch headers and return analysis with security score."""
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            self.url = "https://" + self.url

        self.results = {
            "url": self.url,
            "headers": {},
            "security_headers": {},
            "vulnerable_headers": {},
            "security_score": 0,
        }

        try:
            resp = requests.get(
                self.url,
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )

            # Store all headers
            for key, value in resp.headers.items():
                self.results["headers"][key] = value

            # Security score calculation
            score = 0
            max_score = sum(h["weight"] for h in SECURITY_HEADERS.values())

            # Check for good security headers
            for header, info in SECURITY_HEADERS.items():
                if header in resp.headers:
                    score += info["weight"]
                    self.results["security_headers"][header] = resp.headers[header]

            # Check for bad disclosure headers (penalize)
            for header, info in VULNERABLE_HEADERS.items():
                if header in resp.headers:
                    score -= info["weight"]
                    self.results["vulnerable_headers"][header] = resp.headers[header]

            # Normalize to 0-100
            if max_score > 0:
                score = max(0, min(100, int((score / max_score) * 100)))

            self.results["security_score"] = score
            self.results["status_code"] = resp.status_code
            self.results["content_type"] = resp.headers.get("Content-Type", "N/A")

            # Cookies check
            if "Set-Cookie" in resp.headers:
                cookie_val = resp.headers["Set-Cookie"]
                self.results["cookie_secure"] = "Secure" in cookie_val
                self.results["cookie_httponly"] = "HttpOnly" in cookie_val

        except requests.exceptions.ConnectionError:
            self.results["error"] = "Connection failed"
        except requests.exceptions.Timeout:
            self.results["error"] = "Request timed out"
        except Exception as e:
            self.results["error"] = str(e)

        return self.results
