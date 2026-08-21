# modules/phone_lookup.py
# OrionToolkit - Phone Number Lookup Module

import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COUNTRY_CODES = {
    "1": "US/CA", "44": "UK", "49": "DE", "33": "FR",
    "39": "IT", "34": "ES", "31": "NL", "32": "BE",
    "41": "CH", "43": "AT", "46": "SE", "47": "NO",
    "45": "DK", "48": "PL", "30": "GR", "351": "PT",
    "353": "IE", "358": "FI", "354": "IS", "36": "HU",
    "420": "CZ", "421": "SK", "40": "RO", "359": "BG",
    "7": "RU/KZ", "380": "UA", "375": "BY", "370": "LT",
    "371": "LV", "372": "EE", "81": "JP", "82": "KR",
    "86": "CN", "91": "IN", "92": "PK", "93": "AF",
    "94": "LK", "95": "MM", "60": "MY", "62": "ID",
    "63": "PH", "61": "AU", "64": "NZ", "65": "SG",
    "66": "TH", "84": "VN", "20": "EG", "27": "ZA",
    "212": "MA", "213": "DZ", "216": "TN", "234": "NG",
    "254": "KE", "233": "GH", "251": "ET", "256": "UG",
    "52": "MX", "55": "BR", "54": "AR", "56": "CL",
    "57": "CO", "51": "PE", "58": "VE", "90": "TR",
    "966": "SA", "971": "AE", "972": "IL", "964": "IQ",
    "98": "IR", "965": "KW", "962": "JO", "961": "LB",
    "967": "YE", "968": "OM", "886": "TW", "852": "HK",
}


def validate_phone(number):
    """Validate and parse a phone number, returning country info."""
    cleaned = re.sub(r"[^\d+]", "", number)
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    for code_len in range(1, 4):
        if len(cleaned) > code_len:
            code = cleaned[1:1+code_len]
            if code in COUNTRY_CODES:
                country = COUNTRY_CODES[code]
                local = cleaned[1+code_len:]
                return {
                    "full": cleaned,
                    "country_code": f"+{code}",
                    "country": country,
                    "local_number": local,
                    "valid": True,
                }

    return {
        "full": cleaned,
        "country_code": "Unknown",
        "country": "Unknown",
        "local_number": cleaned[1:] if cleaned.startswith("+") else cleaned,
        "valid": False,
    }


def menu_phone():
    """Interactive phone number lookup."""
    console.print(Panel.fit("[bold cyan]PHONE NUMBER LOOKUP[/bold cyan]", border_style="cyan"))
    number = console.input("[white]Phone number (with country code, e.g. +1234567890): [/white]").strip()
    if not number:
        console.print("[red]Number is required.[/red]")
        return

    info = validate_phone(number)
    table = Table(title="PHONE NUMBER ANALYSIS", border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")
    table.add_row("Full Number", info["full"])
    table.add_row("Country Code", info["country_code"])
    table.add_row("Country", info["country"])
    table.add_row("Local Number", info["local_number"])
    table.add_row("Valid Format", "[green]Yes[/green]" if info["valid"] else "[red]No (unrecognized country code)[/red]")

    if info["valid"]:
        local_len = len(info["local_number"])
        if 7 <= local_len <= 15:
            table.add_row("Length Check", f"[green]{local_len} digits (reasonable)[/green]")
        else:
            table.add_row("Length Check", f"[yellow]{local_len} digits (unusual)[/yellow]")

    console.print(table)
    console.print("\n[dim]Note: Full carrier/owner lookup requires a paid API service.[/dim]")
