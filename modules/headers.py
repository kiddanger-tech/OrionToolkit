import requests
from rich.console import Console
from rich.table import Table

console = Console()


def http_headers(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print(
        f"\n[cyan]Requesting:[/cyan] [bold]{url}[/bold]\n"
    )

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "OrionOSINT/1.0"
            }
        )

        table = Table(
            title="HTTP HEADERS",
            border_style="cyan"
        )

        table.add_column(
            "Header",
            style="bold cyan"
        )

        table.add_column(
            "Value",
            style="white"
        )

        table.add_row(
            "Status Code",
            str(response.status_code)
        )

        table.add_row(
            "Final URL",
            response.url
        )

        for name, value in response.headers.items():
            table.add_row(
                name,
                value
            )

        console.print(table)

    except requests.exceptions.Timeout:
        console.print(
            "[bold red]Request timed out.[/bold red]"
        )

    except requests.exceptions.ConnectionError:
        console.print(
            "[bold red]Could not connect to the website.[/bold red]"
        )

    except requests.exceptions.RequestException as error:
        console.print(
            f"[bold red]Request error:[/bold red] {error}"
        )
