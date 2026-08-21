# modules/subdomain.py
# OrionToolkit - Subdomain Enumeration Module

import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


def crtsh_enum(domain):
    """Fetch subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            entries = resp.json()
            subs = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and n != domain and "*" not in n:
                        subs.add(n)
            return sorted(subs)
    except Exception:
        pass
    return []


def dns_bruteforce(domain, wordlist, threads=20):
    """Brute-force subdomains using a wordlist and DNS resolution."""
    found = []

    def check_sub(sub):
        target = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=5)
            ips = [str(r) for r in answers]
            return (target, ips)
        except Exception:
            return None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console, transient=True,
    ) as progress:
        progress.add_task("[cyan]Brute-forcing subdomains...", total=None)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_sub, s): s for s in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
    return found


def menu_subdomain():
    """Interactive menu for subdomain enumeration."""
    console.print(Panel.fit("[bold cyan]SUBDOMAIN ENUMERATION[/bold cyan]", border_style="cyan"))
    domain = console.input("[white]Domain: [/white]").strip()
    if not domain:
        console.print("[red]Domain is required.[/red]")
        return

    console.print("[dim]1. crt.sh (passive, fast)[/dim]")
    console.print("[dim]2. DNS wordlist brute-force (active, slower)[/dim]")
    console.print("[dim]3. Both[/dim]")
    mode = console.input("[white]Mode [3]: [/white]").strip() or "3"
    results = set()

    if mode in ("1", "3"):
        console.print("\n[cyan]Querying crt.sh...[/cyan]")
        crt_results = crtsh_enum(domain)
        console.print(f"[green]Found {len(crt_results)} subdomains via crt.sh[/green]")
        results.update(crt_results)

    if mode in ("2", "3"):
        wl_path = console.input("[white]Wordlist path: [/white]").strip()
        try:
            with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]File not found: {wl_path}[/red]")
            return
        console.print(f"\n[cyan]Brute-forcing {len(wordlist)} subdomains...[/cyan]")
        brute_results = dns_bruteforce(domain, wordlist)
        console.print(f"[green]Resolved {len(brute_results)} subdomains via DNS[/green]")
        for sub, ips in brute_results:
            results.add(sub)

    if not results:
        console.print("[yellow]No subdomains found.[/yellow]")
        return

    sorted_results = sorted(results)
    table = Table(title=f"SUBDOMAINS FOR {domain}", border_style="cyan")
    table.add_column("#", style="bold cyan")
    table.add_column("Subdomain", style="white")
    for i, sub in enumerate(sorted_results, 1):
        table.add_row(str(i), sub)
    console.print(table)
    console.print(f"\n[bold green]Total: {len(sorted_results)} subdomains[/bold green]")
