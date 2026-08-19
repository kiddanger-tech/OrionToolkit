import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()


def dns_lookup(domain):
    domain = domain.strip().lower()

    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.split("/")[0]

    console.print(
        f"\n[cyan]DNS lookup:[/cyan] [bold]{domain}[/bold]\n"
    )

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]

    table = Table(
        title=f"DNS Records — {domain}",
        border_style="cyan",
    )

    table.add_column("Type", style="bold cyan")
    table.add_column("Records", style="white")

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type
            )

            records = []

            for answer in answers:
                records.append(str(answer))

            table.add_row(
                record_type,
                "\n".join(records)
            )

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            table.add_row(
                record_type,
                "[dim]No record found[/dim]"
            )

        except Exception as error:
            table.add_row(
                record_type,
                f"[red]Error: {error}[/red]"
            )

    console.print(table)
