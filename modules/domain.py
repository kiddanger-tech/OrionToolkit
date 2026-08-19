import socket

from rich.console import Console
from rich.table import Table

console = Console()


def domain_info(domain):
    domain = domain.strip().lower()

    # Remove accidental protocol/path
    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.split("/")[0]

    console.print(
        f"\n[cyan]Looking up:[/cyan] [bold]{domain}[/bold]\n"
    )

    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(domain)

        table = Table(
            title="Domain Information",
            border_style="cyan",
        )

        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")

        table.add_row("Domain", domain)
        table.add_row("Hostname", hostname)

        if aliases:
            table.add_row("Aliases", ", ".join(aliases))
        else:
            table.add_row("Aliases", "None")

        if addresses:
            table.add_row(
                "IP Addresses",
                "\n".join(addresses)
            )
        else:
            table.add_row("IP Addresses", "None")

        console.print(table)

    except socket.gaierror:
        console.print(
            "\n[bold red]Could not resolve this domain.[/bold red]"
        )

    except Exception as error:
        console.print(
            f"\n[bold red]Error:[/bold red] {error}"
        )
