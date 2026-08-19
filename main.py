from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.domain import domain_info
from modules.dns_lookup import dns_lookup
from modules.ip_lookup import ip_lookup, show_my_private_ip
from modules.headers import http_headers

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]ORION OSINT[/bold cyan]\n"
            "[white]Open-Source Intelligence Toolkit[/white]\n"
            "[dim]Version 1.3[/dim]",
            border_style="cyan",
        )
    )


def menu():
    table = Table(
        title="OSINT MODULES",
        border_style="cyan",
    )

    table.add_column("Option", style="bold cyan")
    table.add_column("Module", style="white")
    table.add_column("Status", style="green")

    table.add_row("1", "Domain Information", "READY")
    table.add_row("2", "DNS Lookup", "READY")
    table.add_row("3", "IP Information", "READY")
    table.add_row("4", "My Private IP", "READY")
    table.add_row("5", "HTTP Headers", "READY")
    table.add_row("6", "File Hash", "COMING SOON")
    table.add_row("0", "Exit", "READY")

    console.print(table)


def pause():
    console.input(
        "\n[dim]Press ENTER to continue...[/dim]"
    )


def main():
    while True:
        console.clear()

        banner()
        menu()

        choice = console.input(
            "\n[bold cyan]Select an option:[/bold cyan] "
        ).strip()

        if choice == "0":
            console.print(
                "\n[bold cyan]Thanks for using OrionOSINT![/bold cyan]"
            )
            break

        elif choice == "1":
            console.print(
                "\n[bold cyan]DOMAIN INFORMATION[/bold cyan]"
            )

            domain = console.input(
                "[white]Enter domain: [/white]"
            ).strip()

            if domain:
                domain_info(domain)
            else:
                console.print(
                    "[red]Please enter a domain.[/red]"
                )

            pause()

        elif choice == "2":
            console.print(
                "\n[bold cyan]DNS LOOKUP[/bold cyan]"
            )

            domain = console.input(
                "[white]Enter domain: [/white]"
            ).strip()

            if domain:
                dns_lookup(domain)
            else:
                console.print(
                    "[red]Please enter a domain.[/red]"
                )

            pause()

        elif choice == "3":
            console.print(
                "\n[bold cyan]IP INFORMATION[/bold cyan]"
            )

            ip_address = console.input(
                "[white]Enter IP address: [/white]"
            ).strip()

            if ip_address:
                ip_lookup(ip_address)
            else:
                console.print(
                    "[red]Please enter an IP address.[/red]"
                )

            pause()

        elif choice == "4":
            show_my_private_ip()
            pause()

        elif choice == "5":
            console.print(
                "\n[bold cyan]HTTP HEADERS[/bold cyan]"
            )

            url = console.input(
                "[white]Enter website: [/white]"
            ).strip()

            if url:
                http_headers(url)
            else:
                console.print(
                    "[red]Please enter a website.[/red]"
                )

            pause()

        else:
            console.print(
                "\n[yellow]This module is not available yet.[/yellow]"
            )
            pause()


if __name__ == "__main__":
    main()
