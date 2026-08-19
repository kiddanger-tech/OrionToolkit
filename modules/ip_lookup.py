import ipaddress
import socket

from rich.console import Console
from rich.table import Table

console = Console()


def ip_lookup(ip_address):
    ip_address = ip_address.strip()

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        console.print(
            "\n[bold red]Invalid IP address.[/bold red]"
        )
        return

    table = Table(
        title="IP INFORMATION",
        border_style="cyan"
    )

    table.add_column("Property", style="bold cyan")
    table.add_column("Result", style="white")

    table.add_row("IP Address", str(ip))
    table.add_row(
        "Version",
        "IPv4" if ip.version == 4 else "IPv6"
    )
    table.add_row(
        "Type",
        "Private / Local"
        if ip.is_private
        else "Public"
    )

    if ip.is_private:
        table.add_row(
            "Internet Location",
            "Not available from the private IP alone"
        )
        table.add_row(
            "ISP",
            "Not available from the private IP alone"
        )
        table.add_row(
            "Public Geolocation",
            "Not available from the private IP alone"
        )
    else:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]

            table.add_row(
                "Reverse DNS",
                hostname
            )

        except socket.herror:
            table.add_row(
                "Reverse DNS",
                "No hostname found"
            )

    console.print()
    console.print(table)


def get_local_ip():
    try:
        connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        connection.connect(("8.8.8.8", 80))
        local_ip = connection.getsockname()[0]

        connection.close()

        return local_ip

    except Exception:
        return None


def show_my_private_ip():
    local_ip = get_local_ip()

    if not local_ip:
        console.print(
            "\n[bold red]Could not determine your local IP.[/bold red]"
        )
        return

    console.print(
        "\n[bold cyan]YOUR PRIVATE IP[/bold cyan]"
    )

    ip_lookup(local_ip)
