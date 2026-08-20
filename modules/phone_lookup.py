# modules/phone_lookup.py
# OrionToolkit - Phone Number Lookup Module

import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COUNTRY_CODES = {
    "1": "US/CA", "7": "RU/KZ", "20": "EG", "27": "ZA",
    "30": "GR", "31": "NL", "32": "BE", "33": "FR",
    "34": "ES", "36": "HU", "39": "IT", "40": "RO",
    "41": "CH", "42": "CZ", "43": "AT", "44": "UK",
    "45": "DK", "46": "SE", "47": "NO", "48": "PL",
    "49": "DE", "51": "PE", "52": "MX", "53": "CU",
    "54": "AR", "55": "BR", "56": "CL", "57": "CO",
    "58": "VE", "60": "MY", "61": "AU", "62": "ID",
    "63": "PH", "64": "NZ", "65": "SG", "66": "TH",
    "81": "JP", "82": "KR", "84": "VN", "86": "CN",
    "90": "TR", "91": "IN", "92": "PK", "93": "AF",
    "94": "LK", "95": "MM", "98": "IR", "212": "MA",
    "213": "DZ", "216": "TN", "218": "LY", "220": "GM",
    "221": "SN", "224": "GN", "225": "CI", "230": "MU",
    "233": "GH", "234": "NG", "249": "SD", "251": "ET",
    "254": "KE", "255": "TZ", "256": "UG", "258": "MZ",
    "260": "ZM", "261": "MG", "263": "ZW", "264": "NA",
    "265": "MW", "267": "BW", "268": "SZ", "351": "PT",
    "352": "LU", "353": "IE", "354": "IS", "355": "AL",
    "356": "MT", "357": "CY", "358": "FI", "359": "BG",
    "370": "LT", "371": "LV", "372": "EE", "373": "MD",
    "374": "AM", "375": "BY", "376": "AD", "377": "MC",
    "380": "UA", "381": "RS", "382": "ME", "385": "HR",
    "386": "SI", "387": "BA", "389": "MK", "420": "CZ",
    "421": "SK", "501": "BZ", "502": "GT", "503": "SV",
    "504": "HN", "505": "NI", "506": "CR", "507": "PA",
    "509": "HT", "591": "BO", "592": "GY", "593": "EC",
    "594": "GF", "595": "PY", "596": "MQ", "597": "SR",
    "598": "UY", "599": "NL", "886": "TW", "960": "MV",
    "961": "LB", "962": "JO", "963": "SY", "964": "IQ",
    "965": "KW", "966": "SA", "967": "YE", "968": "OM",
    "970": "PS", "971": "AE", "972": "IL", "973": "BH",
    "974": "QA", "975": "BT", "976": "MN", "977": "NP",
    "992": "TJ", "993": "TM", "994": "AZ", "995": "GE",
    "996": "KG", "998": "UZ",
}


def validate_phone(number):
    """Validate and parse a phone number, returning country info."""
    # Strip all non-digit characters except leading +
    cleaned = re.sub(r"[^\d+]", "", number)
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    # Try to match country code
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


def phone_lookup_online(number):
    """Look up phone number info via free API (numverify.com requires key, so we use a simpler approach)."""
    # Free API: abstractapi.com offers a free tier
    # For now we do local validation + carrier hint from number patterns
    return None


def menu_phone():
    """Interactive phone number lookup."""
    console.print(Panel.fit("[bold cyan]PHONE NUMBER LOOKUP[/bold cyan]", border_style="cyan"))

    number = console.input("[white]Phone number (with country code, e.g. +1234567890): [/white]").strip()
    if not number:
        console.print("[red]Number is required.[/red]")
        return

    info = validate_phone(number)

    table = Table(title=f"PHONE NUMBER ANALYSIS", border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Full Number", info["full"])
    table.add_row("Country Code", info["country_code"])
    table.add_row("Country", info["country"])
    table.add_row("Local Number", info["local_number"])
    table.add_row("Valid Format", "[green]Yes[/green]" if info["valid"] else "[red]No (unrecognized country code)[/red]")

    if info["valid"]:
        # Length check per country (basic)
        local_len = len(info["local_number"])
        if 7 <= local_len <= 15:
            table.add_row("Length Check", f"[green]{local_len} digits (reasonable)[/green]")
        else:
            table.add_row("Length Check", f"[yellow]{local_len} digits (unusual)[/yellow]")

    console.print(table)

    console.print("\n[dim]Note: Full carrier/owner lookup requires a paid API service.[/dim]")
