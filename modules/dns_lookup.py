# modules/dns_lookup.py
# OrionToolkit - DNS Lookup Module

import dns.resolver
from rich.console import Console

console = Console()


class DNSLookup:
    """Perform DNS record lookups for various record types."""

    RECORD_TYPES = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT",
        "SOA", "CAA", "SRV", "PTR", "CERT", "DNAME",
        "SSHFP", "TLSA", "NAPTR",
    ]

    def __init__(self, domain: str):
        self.domain = domain.strip().lower()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def query(self, record_type: str) -> list:
        """Query a specific DNS record type."""
        results = []
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            for rdata in answers:
                results.append(rdata.to_text())
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception:
            pass
        return results

    def query_all(self) -> dict:
        """Query all common DNS record types and return dict of results."""
        results = {}

        for rtype in self.RECORD_TYPES:
            records = self.query(rtype)
            if records:
                results[rtype] = records

        # Add a summary if nothing found
        if not results:
            results["status"] = ["No DNS records found"]

        return results
