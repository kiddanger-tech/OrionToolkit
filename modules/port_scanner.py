# modules/port_scanner.py
# OrionToolkit - TCP Port Scanner Module

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9090: "HTTP-Alt2", 27017: "MongoDB",
    2222: "SSH-Alt", 8081: "HTTP-Alt3", 9200: "Elasticsearch",
    11211: "Memcached",
}


def scan_port(target, port, timeout=1):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return (port, service, "open")
        return None
    except socket.gaierror:
        return ("error", "DNS resolution failed")
    except socket.timeout:
        return None
    except Exception:
        return None


def scan_ports(target, ports, threads=100, timeout=1):
    """Scan multiple TCP ports in parallel."""
    results = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(ports))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for port in ports:
                future = executor.submit(scan_port, target, port, timeout)
                futures[future] = port

            for future in as_completed(futures):
                progress.update(task, advance=1)
                result = future.result()
                if result and result[0] != "error":
                    results.append(result)

    return sorted(results, key=lambda x: x[0])


def menu_port_scanner():
    """Interactive menu for port scanning."""
    console.print(Panel.fit("[bold cyan]PORT SCANNER[/bold cyan]", border_style="cyan"))

    target = console.input("[white]Target (IP or domain): [/white]").strip()
    if not target:
        console.print("[red]Target is required.[/red]")
        return

    mode = console.input("[white]Scan mode: (1) Common ports  (2) Custom range  (3) Top 1000 [1]: [/white]").strip() or "1"

    if mode == "1":
        ports = list(COMMON_PORTS.keys())
    elif mode == "2":
        range_str = console.input("[white]Port range (e.g. 1-1024 or 1,22,80,443): [/white]").strip()
        if "-" in range_str:
            start, end = range_str.split("-")
            ports = list(range(int(start.strip()), int(end.strip()) + 1))
        elif "," in range_str:
            ports = [int(p.strip()) for p in range_str.split(",")]
        else:
            ports = [int(range_str)]
    else:
        ports = list(COMMON_PORTS.keys()) + [4433, 5000, 5555, 7000, 8000, 8001, 8888, 9000, 9091, 10000, 27017, 50070, 50030]

    threads = int(console.input("[white]Threads [100]: [/white]").strip() or "100")
    timeout = float(console.input("[white]Timeout (seconds) [1]: [/white]").strip() or "1")

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print("[red]Could not resolve target.[/red]")
        return

    console.print(f"\n[dim]Target: {target} -> {ip}[/dim]")
    console.print(f"[dim]Ports to scan: {len(ports)}[/dim]\n")

    results = scan_ports(target, ports, threads, timeout)

    if not results:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title=f"OPEN PORTS — {target} ({ip})", border_style="cyan")
    table.add_column("Port", style="bold cyan")
    table.add_column("Service", style="white")
    table.add_column("Status", style="green")

    for port, service, status in results:
        table.add_row(str(port), service, status)

    console.print(table)
    console.print(f"\n[bold green]Total open ports: {len(results)}[/bold green]")
