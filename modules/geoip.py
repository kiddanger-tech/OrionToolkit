# modules/geoip.py
# OrionToolkit - GeoIP Lookup Module

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def geoip_lookup(query=None):
    """
    Look up geolocation data for an IP address.
    If query is None, looks up the current IP.
    Uses ip-api.com (free, no key required).
    """
    if query:
        url = f"http://ip-api.com/json/{query}?fields=status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"
    else:
        url = "http://ip-api.com/json/?fields=status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"

    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "OrionToolkit/1.0"})
        data = resp.json()

        if data.get("status") == "fail":
            console.print(f"[red]Lookup failed: {data.get('message', 'Unknown error')}[/red]")
            return None

        return data

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Connection error: {e}[/red]")
        return None


def display_geoip(data):
    """Display GeoIP data in a Rich table."""
    if not data:
        return

    table = Table(title=f"GEOIP — {data.get('query', 'N/A')}", border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    fields = [
        ("IP Address", "query"),
        ("Country", "country"),
        ("Country Code", "countryCode"),
        ("Region", "regionName"),
        ("Region Code", "region"),
        ("City", "city"),
        ("ZIP / Postal", "zip"),
        ("Latitude", "lat"),
        ("Longitude", "lon"),
        ("Timezone", "timezone"),
        ("ISP", "isp"),
        ("Organization", "org"),
        ("AS Number", "as"),
        ("AS Name", "asname"),
        ("Mobile Network", "mobile"),
        ("Proxy/VPN", "proxy"),
        ("Hosting", "hosting"),
    ]

    for label, key in fields:
        val = data.get(key)
        if val is not None and val != "":
            if isinstance(val, bool):
                val = "Yes" if val else "No"
            table.add_row(label, str(val))

    console.print(table)


def menu_geoip():
    """Interactive GeoIP menu."""
    console.print(Panel.fit("[bold cyan]GEOIP LOOKUP[/bold cyan]", border_style="cyan"))

    query = console.input("[white]IP address or domain (Enter for your own IP): [/white]").strip() or None

    console.print("[cyan]Looking up...[/cyan]")
    data = geoip_lookup(query)

    if data:
        display_geoip(data)
