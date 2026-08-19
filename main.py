from rich.console import Console
from rich.panel import Panel

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]ORION OSINT[/bold cyan]\n"
            "[white]Open-Source Intelligence Toolkit[/white]\n"
            "[dim]Version 1.0[/dim]",
            border_style="cyan"
        )
    )


def menu():
    console.print("\n[bold cyan]OSINT MODULES[/bold cyan]\n")

    console.print("[1] Domain Information")
    console.print("[2] DNS Lookup")
    console.print("[3] IP Information")
    console.print("[4] HTTP Headers")
    console.print("[5] File Hash")
    console.print("[0] Exit")


def main():
    banner()

    while True:
        menu()

        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            console.print("\n[cyan]Goodbye![/cyan]")
            break

        console.print(
            f"\n[yellow]Module {choice} is not implemented yet.[/yellow]"
        )


if __name__ == "__main__":
    main()
