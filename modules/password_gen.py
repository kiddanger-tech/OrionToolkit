# modules/password_gen.py
# OrionToolkit - Password Generator Module

import secrets
import string
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

console = Console()


def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True, count=1):
    """Generate one or more secure random passwords."""
    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    if not chars:
        chars = string.ascii_letters + string.digits

    passwords = []
    for _ in range(count):
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        passwords.append(pwd)

    return passwords


def estimate_entropy(length, charset_size):
    """Calculate entropy in bits."""
    from math import log2
    return length * log2(charset_size)


def menu_password_gen():
    """Interactive password generator."""
    console.print(Panel.fit("[bold cyan]PASSWORD GENERATOR[/bold cyan]", border_style="cyan"))

    length = int(console.input("[white]Password length [16]: [/white]").strip() or "16")
    count = int(console.input("[white]Number of passwords [5]: [/white]").strip() or "5")

    console.print("[dim]Character sets to include:[/dim]")
    use_lower = console.input("[white]Lowercase (a-z) [Y/n]: [/white]").strip().lower() != "n"
    use_upper = console.input("[white]Uppercase (A-Z) [Y/n]: [/white]").strip().lower() != "n"
    use_digits = console.input("[white]Digits (0-9) [Y/n]: [/white]").strip().lower() != "n"
    use_symbols = console.input("[white]Symbols (!@#...) [y/N]: [/white]").strip().lower() == "y"

    passwords = generate_password(length, use_lower, use_upper, use_digits, use_symbols, count)

    # Calculate charset size
    charset_size = 0
    if use_lower:
        charset_size += 26
    if use_upper:
        charset_size += 26
    if use_digits:
        charset_size += 10
    if use_symbols:
        charset_size += len(string.punctuation)

    entropy = estimate_entropy(length, charset_size)

    table = Table(title=f"GENERATED PASSWORDS (length={length}, {count} passwords)", border_style="cyan")
    table.add_column("#", style="bold cyan")
    table.add_column("Password", style="white")
    table.add_column("Entropy", style="green")

    for i, pwd in enumerate(passwords, 1):
        table.add_row(str(i), pwd, f"{entropy:.1f} bits")

    console.print(table)

    # Strength indicator
    if entropy < 40:
        strength = "[red]Weak[/red]"
    elif entropy < 60:
        strength = "[yellow]Moderate[/yellow]"
    elif entropy < 80:
        strength = "[green]Strong[/green]"
    else:
        strength = "[bold green]Very Strong[/bold green]"

    console.print(f"\nEntropy per password: [bold]{entropy:.1f} bits[/bold] — {strength}")
    console.print(f"Charset size: {charset_size} characters")
    console.print("[dim]These passwords use secrets.choice() — cryptographically secure.[/dim]")
