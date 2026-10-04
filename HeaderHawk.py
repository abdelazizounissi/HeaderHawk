import argparse
import sys

import httpx
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

def check_hsts(value):
    max_age = None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=")[1].strip('"'))
            except ValueError:
                pass

    if max_age is None:
        return "weak", "No valid max-age found"
    if max_age == 0:
        return "weak", "max-age=0 turns HSTS off"
    if max_age < 31536000:
        return "weak", f"max-age is only {max_age} seconds (less than 1 year)"
    return "ok", "Present with a max-age of at least 1 year"


def check_csp(value):
    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return "weak", "Contains unsafe-inline or unsafe-eval"
    return "ok", "Present"


def check_nosniff(value):
    if value.strip().lower() == "nosniff":
        return "ok", "Set to nosniff"
    return "weak", f"Expected nosniff, got {value}"


def check_xfo(value):
    if value.strip().lower() in ("deny", "sameorigin"):
        return "ok", "Set to DENY or SAMEORIGIN"
    return "weak", f"Unexpected value: {value}"


def check_present(value):
    return "ok", "Present"


RULES = [
    {"header": "strict-transport-security", "severity": "high",   "check": check_hsts},
    {"header": "content-security-policy",   "severity": "high",   "check": check_csp},
    {"header": "x-content-type-options",    "severity": "medium", "check": check_nosniff},
    {"header": "x-frame-options",           "severity": "medium", "check": check_xfo},
    {"header": "referrer-policy",           "severity": "low",    "check": check_present},
    {"header": "permissions-policy",        "severity": "low",    "check": check_present},
]


def scan(headers):
    headers = {k.lower(): v for k, v in headers.items()}
    results = []
    for rule in RULES:
        value = headers.get(rule["header"])
        if value is None:
            status, note = "missing", "Header is not set"
        else:
            status, note = rule["check"](value)
        results.append((rule["header"], rule["severity"], status, note))
    return results

WEIGHTS = {"high": 25, "medium": 15, "low": 10}
CREDIT = {"ok": 1.0, "weak": 0.5, "missing": 0.0}


def compute_score(results):
    earned = 0
    possible = 0
    for header, severity, status, note in results:
        weight = WEIGHTS[severity]
        possible += weight
        earned += weight * CREDIT[status]
    return round(earned / possible * 100)


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

console = Console()
TOOL_NAME = "HeaderHawk"   # change this to whatever you want

FIXES = {
    "strict-transport-security": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "content-security-policy": "Content-Security-Policy: default-src 'self'",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "x-frame-options": "X-Frame-Options: DENY",
    "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
}

STATUS_COLOR = {"ok": "green", "weak": "yellow", "missing": "red"}
GRADE_COLOR = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}


def banner():
    art = pyfiglet.figlet_format(TOOL_NAME, font="slant")
    console.print(art, style="bold cyan", markup=False, highlight=False)
    console.print("HTTP security header scanner", style="bold")
    console.print("Only scan sites you own or have permission to test.\n", style="dim")


def fetch(url, timeout):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    console.print(f"[bold cyan][1/3][/] Fetching [underline]{url}[/] ...")
    try:
        with console.status("Waiting for the server...", spinner="dots"):
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.InvalidURL:
        console.print(f"Error: '{url}' is not a valid URL.", style="bold red", markup=False)
        console.print("Tip: try something like https://example.com", style="dim", markup=False)
        return None
    except httpx.TimeoutException:
        console.print(f"Error: timed out after {timeout} seconds.", style="bold red", markup=False)
        console.print("Tip: try a longer wait, e.g. --timeout 20", style="dim", markup=False)
        return None
    except httpx.HTTPError as e:
        console.print(f"Error: could not connect ({type(e).__name__}).", style="bold red", markup=False)
        console.print("Tip: check the spelling and your internet connection.", style="dim", markup=False)
        return None
    console.print(f"      Got HTTP {response.status_code}\n")
    return response


def print_report(response, results):
    console.print("[bold cyan][2/3][/] Checking security headers...\n")

    table = Table(title=f"Headers for {response.url}", header_style="bold")
    table.add_column("header")
    table.add_column("status")
    table.add_column("severity")
    table.add_column("note", overflow="fold")
    for header, severity, status, note in results:
        color = STATUS_COLOR[status]
        table.add_row(header, f"[{color}]{status}[/]", severity, note)
    console.print(table)

    console.print("\n[bold cyan][3/3][/] Result\n")
    score = compute_score(results)
    grade = grade_for(score)
    color = GRADE_COLOR[grade]
    console.print(Panel(f"Grade: [bold {color}]{grade}[/]\nScore: {score} / 100",
                        expand=False, border_style=color))

    problems = [r for r in results if r[2] != "ok"]
    if problems:
        console.print("\n[bold]Recommendations:[/]")
        for header, severity, status, note in problems:
            fix = FIXES.get(header, "see docs")
            console.print(f"  [yellow]-[/] {header} ({status})")
            console.print(f"      add: {fix}", style="dim", markup=False)
    else:
        console.print("\n[green]Nothing to fix. Nice![/]")


def main():
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description="Grade a website's security headers from A to F.",
        epilog="examples:\n"
               "  python scanner.py https://github.com\n"
               "  python scanner.py example.com --timeout 5\n"
               "  python scanner.py            (it will ask you for a URL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="the site to scan, e.g. https://github.com")
    parser.add_argument("--timeout", type=float, default=10, help="seconds to wait (default 10)")
    args = parser.parse_args()

    banner()

    url = args.url
    if url is None:
        console.print("No URL given. Type one below (or run with --help for options).", style="dim")
        url = console.input("[bold]Enter a URL to scan:[/] ").strip()
        console.print()
        if not url:
            console.print("Nothing entered, exiting.", style="red")
            sys.exit(1)

    response = fetch(url, args.timeout)
    if response is None:
        sys.exit(1)

    print_report(response, scan(response.headers))


if __name__ == "__main__":
    main()