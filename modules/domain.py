# modules/domain.py
# OrionToolkit - Domain Analysis Module

import socket
from rich.console import Console

console = Console()


class DomainAnalyzer:
    """Analyze domain information including hostname, aliases, and IP addresses."""

    def __init__(self, domain: str):
        self.domain = domain.strip().lower()
        self.results = {}

    def analyze(self) -> dict:
        """Perform full domain analysis and return results dict."""
        self.results = {
            "domain": self.domain,
            "ip_addresses": [],
            "aliases": [],
            "errors": [],
        }

        try:
            info = socket.gethostbyname_ex(self.domain)
            self.results["canonical_name"] = info[0]
            self.results["aliases"] = info[1]
            self.results["ip_addresses"] = info[2]
            self.results["ip_count"] = len(info[2])
        except socket.gaierror:
            self.results["errors"].append("Could not resolve domain")
        except Exception as e:
            self.results["errors"].append(str(e))

        # Try to get additional IP info for each address
        ip_info = {}
        for ip in self.results.get("ip_addresses", []):
            try:
                host = socket.gethostbyaddr(ip)
                ip_info[ip] = host[0]
            except (socket.herror, socket.gaierror):
                ip_info[ip] = "No reverse DNS"
            except Exception:
                ip_info[ip] = "Unknown"

        if ip_info:
            self.results["reverse_dns"] = ip_info

        return self.results
