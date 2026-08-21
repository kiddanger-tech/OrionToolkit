from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.domain import domain_info
from modules.dns_lookup import dns_lookup
from modules.ip_lookup import ip_lookup, show_my_private_ip
from modules.headers import http_headers
from modules.hashing import file_hash
from modules.bruteforce import menu_bruteforce
from modules.subdomain import menu_subdomain
from modules.port_scanner import menu_port_scanner
from modules.dir_fuzzer import menu_dir_fuzzer
from modules.whois_lookup import menu_whois
from modules.geoip import menu_geoip
from modules.ssl_checker import menu_ssl
from modules.phone_lookup import menu_phone
from modules.password_gen import menu_password_gen

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]ORION OSINT[/bold cyan]\n"
            "[white]Open-Source Intelligence Toolkit[/white]\n"
            "[dim]Version 2.0[/dim]",
            border_style="cyan",
        )
    )


def menu():
    table = Table(
        title="OSINT + RECON MODULES",
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
    table.add_row("6", "File Hash", "READY")
    table.add_row("7", "Login Brute-Force", "READY")
    table.add_row("8", "Subdomain Enumeration", "READY")
    table.add_row("9", "Port Scanner", "READY")
    table.add_row("10", "Directory Fuzzer", "READY")
    table.add_row("11", "Whois Lookup", "READY")
    table.add_row("12", "GeoIP Lookup", "READY")
    table.add_row("13", "SSL Certificate Checker", "READY")
    table.add_row("14", "Phone Number Lookup", "READY")
    table.add_row("15", "Password Generator", "READY")
    table.add_row("0", "Exit", "READY")

    console.print(table)


def pause():
    console.input("\n[dim]Press ENTER to continue...[/dim]")


def main():
    while True:
        console.clear()
        banner()
        menu()

        choice = console.input(
            "\n[bold cyan]Select an option:[/bold cyan] "
        ).strip()

        # --- Exit ---
        if choice == "0":
            console.print(
                "\n[bold cyan]Thanks for using OrionOSINT![/bold cyan]"
            )
            break

        # --- 1: Domain Information ---
        elif choice == "1":
            console.print("\n[bold cyan]DOMAIN INFORMATION[/bold cyan]")
            domain = console.input("[white]Enter domain: [/white]").strip()
            if domain:
                domain_info(domain)
            else:
                console.print("[red]Please enter a domain.[/red]")
            pause()

        # --- 2: DNS Lookup ---
        elif choice == "2":
            console.print("\n[bold cyan]DNS LOOKUP[/bold cyan]")
            domain = console.input("[white]Enter domain: [/white]").strip()
            if domain:
                dns_lookup(domain)
            else:
                console.print("[red]Please enter a domain.[/red]")
            pause()

        # --- 3: IP Information ---
        elif choice == "3":
            console.print("\n[bold cyan]IP INFORMATION[/bold cyan]")
            ip_address = console.input("[white]Enter IP address: [/white]").strip()
            if ip_address:
                ip_lookup(ip_address)
            else:
                console.print("[red]Please enter an IP address.[/red]")
            pause()

        # --- 4: My Private IP ---
        elif choice == "4":
            show_my_private_ip()
            pause()

        # --- 5: HTTP Headers ---
        elif choice == "5":
            console.print("\n[bold cyan]HTTP HEADERS[/bold cyan]")
            url = console.input("[white]Enter website: [/white]").strip()
            if url:
                http_headers(url)
            else:
                console.print("[red]Please enter a website.[/red]")
            pause()

        # --- 6: File Hash ---
        elif choice == "6":
            console.print("\n[bold cyan]FILE HASH[/bold cyan]")
            filepath = console.input("[white]Enter file path: [/white]").strip()
            if filepath:
                file_hash(filepath)
            else:
                console.print("[red]Please enter a file path.[/red]")
            pause()

        # --- 7: Login Brute-Force ---
        elif choice == "7":
            menu_bruteforce()
            pause()

        # --- 8: Subdomain Enumeration ---
        elif choice == "8":
            menu_subdomain()
            pause()

        # --- 9: Port Scanner ---
        elif choice == "9":
            menu_port_scanner()
            pause()

        # --- 10: Directory Fuzzer ---
        elif choice == "10":
            menu_dir_fuzzer()
            pause()

        # --- 11: Whois Lookup ---
        elif choice == "11":
            menu_whois()
            pause()

        # --- 12: GeoIP Lookup ---
        elif choice == "12":
            menu_geoip()
            pause()

        # --- 13: SSL Certificate Checker ---
        elif choice == "13":
            menu_ssl()
            pause()

        # --- 14: Phone Number Lookup ---
        elif choice == "14":
            menu_phone()
            pause()

        # --- 15: Password Generator ---
        elif choice == "15":
            menu_password_gen()
            pause()

        # --- Invalid ---
        else:
            console.print("\n[yellow]This module is not available yet.[/yellow]")
            pause()


if __name__ == "__main__":
    main()
