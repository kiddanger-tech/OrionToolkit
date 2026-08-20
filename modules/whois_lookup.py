# modules/whois_lookup.py
# OrionToolkit - Whois Lookup Module

import socket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "dev": "whois.nic.dev",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "ai": "whois.nic.ai",
    "in": "whois.registry.in",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "ru": "whois.tcinet.ru",
    "br": "whois.registro.br",
    "jp": "whois.jprs.jp",
    "fr": "whois.nic.fr",
    "au": "whois.audns.net.au",
}


def get_whois_server(domain):
    """Determine the appropriate whois server from the TLD."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return WHOIS_SERVERS.get(tld, "whois.iana.org")


def whois_query(domain, server="whois.iana.org", port=43, timeout=10):
    """Perform a raw whois query."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.send(f"{domain}\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"


def menu_whois():
    """Interactive whois lookup."""
    console.print(Panel.fit("[bold cyan]WHOIS LOOKUP[/bold cyan]", border_style="cyan"))

    domain = console.input("[white]Domain: [/white]").strip()
    if not domain:
        console.print("[red]Domain is required.[/red]")
        return

    # Remove protocol and path if pasted as URL
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    console.print(f"\n[cyan]Looking up {domain}...[/cyan]")

    server = get_whois_server(domain)
    console.print(f"[dim]Whois server: {server}[/dim]")

    raw = whois_query(domain, server)

    if raw.startswith("Error"):
        console.print(f"[red]{raw}[/red]")
        return

    # Parse key fields
    info = {}
    lines = raw.split("\n")
    for line in lines:
        line_lower = line.lower()
        for key in ["domain name", "registrar", "creation date", "expiry date",
                     "registrant", "admin", "name server", "status", "dnssec",
                     "registrant organization", "registrant country", "registrant email"]:
            if line_lower.startswith(key):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    info[parts[0].strip()] = parts[1].strip()

    if info:
        table = Table(title=f"WHOIS — {domain}", border_style="cyan")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")
        for key, val in info.items():
            table.add_row(key.capitalize(), val)
        console.print(table)
    else:
        # Show raw output if parsing fails
        console.print(Panel(raw[:3000], title=f"Raw Whois — {domain}", border_style="cyan"))

    console.print(f"\n[dim]Server: {server} | Lines: {len(lines)}[/dim]")
