# modules/ssl_checker.py
# OrionToolkit - SSL Certificate Checker Module

import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def check_ssl(hostname, port=443, timeout=10):
    """Fetch and display SSL certificate details for a hostname."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        table = Table(title=f"SSL CERTIFICATE — {hostname}:{port}", border_style="cyan")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")

        subject = dict(x[0] for x in cert.get("subject", []))
        table.add_row("Common Name (CN)", subject.get("commonName", "N/A"))
        table.add_row("Organization", subject.get("organizationName", "N/A"))
        table.add_row("Country", subject.get("countryName", "N/A"))

        issuer = dict(x[0] for x in cert.get("issuer", []))
        table.add_row("Issuer CN", issuer.get("commonName", "N/A"))
        table.add_row("Issuer Org", issuer.get("organizationName", "N/A"))

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        try:
            nb = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            na = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            days_left = (na - now).days
            table.add_row("Issued", nb.strftime("%Y-%m-%d %H:%M:%S"))
            table.add_row("Expires", na.strftime("%Y-%m-%d %H:%M:%S"))
            if days_left < 0:
                table.add_row("Status", "[red]EXPIRED[/red]")
            elif days_left < 30:
                table.add_row("Status", f"[yellow]Expiring soon ({days_left} days)[/yellow]")
            else:
                table.add_row("Status", f"[green]Valid ({days_left} days remaining)[/green]")
        except Exception:
            table.add_row("Not Before", not_before)
            table.add_row("Not After", not_after)

        sans = [ext[1] for ext in cert.get("subjectAltName", []) if ext[0] == "DNS"]
        if sans:
            table.add_row("Subject Alt Names", ", ".join(sans[:10]))
            if len(sans) > 10:
                table.add_row("", f"... and {len(sans)-10} more")

        table.add_row("Serial Number", cert.get("serialNumber", "N/A")[:30])
        table.add_row("SSL/TLS Version", ssock.version())
        console.print(table)

    except Exception as e:
        console.print(f"[red]SSL error: {e}[/red]")


def menu_ssl():
    """Interactive SSL checker menu."""
    console.print(Panel.fit("[bold cyan]SSL CERTIFICATE CHECKER[/bold cyan]", border_style="cyan"))
    hostname = console.input("[white]Hostname (e.g. example.com): [/white]").strip()
    if not hostname:
        console.print("[red]Hostname is required.[/red]")
        return
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    port_input = console.input("[white]Port [443]: [/white]").strip()
    port = int(port_input) if port_input else 443
    check_ssl(hostname, port)
