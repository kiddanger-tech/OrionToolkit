from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.domain import domain_info

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]ORION OSINT[/bold cyan]\n"
            "[white]Open-Source Intelligence Toolkit[/white]\n"
            "[dim]Version 1.0[/dim]",
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
    table.add_row("2", "DNS Lookup", "COMING SOON")
    table.add_row("3", "IP Information", "COMING SOON")
    table.add_row("4", "HTTP Headers", "COMING SOON")
    table.add_row("5", "File Hash", "COMING SOON")
    table.add_row("0", "Exit", "READY")

    console.print(table)


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
            console.print("\n[bold cyan]DOMAIN INFORMATION[/bold cyan]")

            domain = console.input(
                "[white]Enter domain: [/white]"
            ).strip()

            if domain:
                domain_info(domain)
            else:
                console.print(
                    "[red]Please enter a domain.[/red]"
                )

            console.input(
                "\n[dim]Press ENTER to continue...[/dim]"
            )

        else:
            console.print(
                "\n[yellow]This module is not available yet.[/yellow]"
            )

            console.input(
                "\n[dim]Press ENTER to continue...[/dim]"
            )


if __name__ == "__main__":
    main()
