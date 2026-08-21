# modules/ip_lookup.py
# OrionToolkit - IP Lookup Module

import ipaddress
import socket
import requests
from rich.console import Console
from rich.table import Table

console = Console()


class IPLookup:
    """Look up IP address information, geolocation, and reverse DNS."""

    def __init__(self, ip_address: str):
        self.ip_address = ip_address.strip()
        self.results = {}

    def lookup(self) -> dict:
        """Perform comprehensive IP lookup and return results dict."""
        self.results = {
            "ip_address": self.ip_address,
            "valid": False,
            "version": None,
            "type": None,
        }

        # Validate IP
        try:
            ip = ipaddress.ip_address(self.ip_address)
            self.results["valid"] = True
            self.results["version"] = f"IPv{ip.version}"
            self.results["type"] = "Private" if ip.is_private else "Public"
            self.results["loopback"] = ip.is_loopback
            self.results["multicast"] = ip.is_multicast
            self.results["global"] = ip.is_global if hasattr(ip, "is_global") else None
        except ValueError:
            self.results["errors"] = ["Invalid IP address format"]
            return self.results

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(self.ip_address)
            self.results["reverse_dns"] = hostname[0]
            self.results["reverse_aliases"] = hostname[1]
        except (socket.herror, socket.gaierror):
            self.results["reverse_dns"] = "No reverse DNS record"
        except Exception:
            self.results["reverse_dns"] = "Lookup failed"

        # GeoIP via ip-api.com (free, no key needed)
        if not ip.is_private and not ip.is_loopback:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{self.ip_address}",
                    params={"fields": "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting"},
                    timeout=5,
                    headers={"User-Agent": "OrionToolkit/1.0"},
                )
                geo = resp.json()
                if geo.get("status") == "success":
                    self.results["geolocation"] = {
                        "country": geo.get("country"),
                        "country_code": geo.get("countryCode"),
                        "region": geo.get("regionName"),
                        "city": geo.get("city"),
                        "zip": geo.get("zip"),
                        "latitude": geo.get("lat"),
                        "longitude": geo.get("lon"),
                        "timezone": geo.get("timezone"),
                        "isp": geo.get("isp"),
                        "organization": geo.get("org"),
                        "asn": geo.get("as"),
                        "asn_name": geo.get("asname"),
                        "proxy": geo.get("proxy"),
                        "hosting": geo.get("hosting"),
                    }
            except Exception:
                pass

        return self.results
