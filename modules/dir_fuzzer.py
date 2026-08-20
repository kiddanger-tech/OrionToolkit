# modules/dir_fuzzer.py
# OrionToolkit - Directory/Path Fuzzer Module

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".txt", ".bak", ".old", ".json", ".xml"]


def check_path(base_url, path, extensions, timeout=5, verify_ssl=False):
    """Check if a path exists on the target server."""
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}

    for ext in extensions:
        full_path = path + ext
        url = f"{base_url.rstrip('/')}/{full_path.lstrip('/')}"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=False)
            if resp.status_code in (200, 201, 204):
                results.append((full_path, resp.status_code, len(resp.content)))
            elif resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                results.append((full_path, resp.status_code, location[:60]))
            elif resp.status_code == 401:
                results.append((full_path, resp.status_code, "Auth Required"))
            elif resp.status_code == 403:
                results.append((full_path, resp.status_code, "Forbidden"))
            elif resp.status_code == 500:
                results.append((full_path, resp.status_code, "Server Error"))
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pass
    return results


def menu_dir_fuzzer():
    """Interactive menu for directory fuzzing."""
    console.print(Panel.fit("[bold cyan]DIRECTORY FUZZER[/bold cyan]", border_style="cyan"))

    base_url = console.input("[white]Base URL (e.g. https://example.com): [/white]").strip()
    if not base_url:
        console.print("[red]URL is required.[/red]")
        return

    wordlist_path = console.input("[white]Wordlist path: [/white]").strip()
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]File not found: {wordlist_path}[/red]")
        return

    ext_choice = console.input("[white]Check common extensions? (y/n) [y]: [/white]").strip().lower() or "y"
    exts = EXTENSIONS if ext_choice == "y" else [""]

    threads = int(console.input("[white]Threads [20]: [/white]").strip() or "20")
    timeout = int(console.input("[white]Timeout [5]: [/white]").strip() or "5")

    console.print(f"\n[dim]Testing {len(wordlist)} paths with {len(exts)} extension(s)...[/dim]\n")

    found = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Fuzzing...", total=len(wordlist))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for word in wordlist:
                future = executor.submit(check_path, base_url, word, exts, timeout, False)
                futures[future] = word

            for future in as_completed(futures):
                progress.update(task, advance=1)
                results = future.result()
                if results:
                    found.extend(results)

    if not found:
        console.print("[yellow]No accessible paths found.[/yellow]")
        return

    table = Table(title=f"FOUND PATHS — {base_url}", border_style="cyan")
    table.add_column("Path", style="bold cyan")
    table.add_column("Status", style="white")
    table.add_column("Size / Redirect", style="green")

    for path, status, extra in sorted(found, key=lambda x: (x[1], x[0])):
        color = "green" if status == 200 else "yellow" if status in (301, 302, 307, 308) else "red"
        table.add_row(f"/{path}", f"[{color}]{status}[/{color}]", str(extra))

    console.print(table)
    console.print(f"\n[bold green]Total discovered: {len(found)}[/bold green]")
