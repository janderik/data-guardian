import sys
import time
import logging
import argparse
from pathlib import Path
from typing import List, Optional

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def _ensure_rich():
    if not RICH_AVAILABLE:
        print("Error: 'rich' library is required. Install with: pip install rich")
        sys.exit(1)


console = Console() if RICH_AVAILABLE else None


def main():
    parser = argparse.ArgumentParser(
        prog="dataguardian",
        description="🛡️  DataGuardian - Data Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dataguardian scan ./project
  dataguardian scan ./data --sensitivity high --threads 8
  dataguardian scan ./secrets --output report.json
  dataguardian scan ./files --format html --output report.html
  dataguardian scan-db --db-type sqlite --db-path data.db
  dataguardian scan-db --db-type postgresql --host localhost --dbname mydb --user admin
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan files and directories")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    scan_parser.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium", help="Detection sensitivity")
    scan_parser.add_argument("--threads", type=int, default=4, help="Number of threads")
    scan_parser.add_argument("--output", "-o", default="", help="Output file path")
    scan_parser.add_argument("--format", choices=["json", "html"], default="console", help="Output format")
    scan_parser.add_argument("--max-size", type=int, default=10, help="Max file size in MB")
    scan_parser.add_argument("--max-depth", type=int, default=None, help="Max directory depth")
    scan_parser.add_argument("--no-binary", action="store_true", default=True, help="Skip binary files")
    scan_parser.add_argument("--rules", default="", help="Custom rules file (YAML/JSON)")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    db_parser = subparsers.add_parser("scan-db", help="Scan databases")
    db_parser.add_argument("--db-type", choices=["postgresql", "mysql", "sqlite"], default="sqlite", help="Database type")
    db_parser.add_argument("--host", default="localhost", help="Database host")
    db_parser.add_argument("--port", type=int, default=0, help="Database port")
    db_parser.add_argument("--dbname", default="", help="Database name")
    db_parser.add_argument("--db-path", default="", help="SQLite database path")
    db_parser.add_argument("--user", default="", help="Database user")
    db_parser.add_argument("--password", default="", help="Database password")
    db_parser.add_argument("--output", "-o", default="", help="Output file path")
    db_parser.add_argument("--format", choices=["json", "html"], default="console", help="Output format")
    db_parser.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium", help="Detection sensitivity")
    db_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "scan-db":
        cmd_scan_db(args)
    else:
        parser.print_help()


def cmd_scan(args):
    _ensure_rich()

    from scanners.file_scanner import FileScanner
    from scanners.filesystem_scanner import FilesystemScanner
    from detectors.pii_detector import PIIDetector
    from detectors.credit_card import CreditCardDetector
    from detectors.credentials import CredentialDetector
    from detectors.custom_rules import CustomRulesDetector
    from reporters.json_reporter import JSONReporter
    from reporters.html_reporter import HTMLReporter

    path = args.path
    if not Path(path).exists():
        console.print(f"[red]✗ Error: Path '{path}' does not exist[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]🛡️  DataGuardian Scan[/bold cyan]\n"
        f"[white]Target:[/white] [yellow]{path}[/yellow]\n"
        f"[white]Sensitivity:[/white] [yellow]{args.sensitivity}[/yellow]\n"
        f"[white]Max Depth:[/white] [yellow]{args.max_depth or 'unlimited'}[/yellow]",
        title="DataGuardian",
        border_style="cyan",
    ))

    scanner = FilesystemScanner(
        sensitivity=args.sensitivity,
        max_size_mb=args.max_size,
        max_depth=args.max_depth,
        skip_binary=args.no_binary,
    )

    pii_detector = PIIDetector(sensitivity=args.sensitivity)
    cc_detector = CreditCardDetector(sensitivity=args.sensitivity)
    cred_detector = CredentialDetector(sensitivity=args.sensitivity)

    scanner.add_detector(pii_detector)
    scanner.add_detector(cc_detector)
    scanner.add_detector(cred_detector)

    if args.rules:
        try:
            custom = CustomRulesDetector(rules_file=args.rules, sensitivity=args.sensitivity)
            scanner.add_detector(custom)
            console.print(f"[green]✓ Loaded custom rules from: {args.rules}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to load custom rules: {e}[/red]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=None)
        start = time.time()
        result = scanner.scan(path)
        progress.update(task, completed=True)

    duration = time.time() - start
    result.scan_duration = duration

    if result.errors:
        for err in result.errors[:5]:
            console.print(f"[yellow]⚠ {err}[/yellow]")

    _display_results(result, args)


def cmd_scan_db(args):
    _ensure_rich()

    from scanners.database_scanner import DatabaseScanner
    from reporters.json_reporter import JSONReporter
    from reporters.html_reporter import HTMLReporter

    if args.db_type == "sqlite" and not args.db_path:
        console.print("[red]✗ Error: --db-path is required for SQLite[/red]")
        sys.exit(1)

    scanner = DatabaseScanner(sensitivity=args.sensitivity)

    console.print(Panel(
        f"[bold cyan]🛡️  DataGuardian Database Scan[/bold cyan]\n"
        f"[white]Database:[/white] [yellow]{args.db_type}[/yellow]\n"
        f"[white]Host:[/white] [yellow]{args.host or 'N/A'}[/yellow]",
        title="DataGuardian",
        border_style="cyan",
    ))

    start = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("[cyan]Scanning database...", total=None)
        result = scanner.scan(
            target=args.db_path or "",
            db_type=args.db_type,
            host=args.host,
            port=args.port if args.port else None,
            dbname=args.dbname,
            user=args.user,
            password=args.password,
        )

    duration = time.time() - start
    result.scan_duration = duration

    _display_results(result, args)


def _display_results(result, args):
    from reporters.json_reporter import JSONReporter
    from reporters.html_reporter import HTMLReporter

    output_format = getattr(args, "format", "console")
    output_path = getattr(args, "output", "")

    if output_format == "json":
        reporter = JSONReporter()
        output = reporter.generate(result, output_path)
        if not output_path:
            print(output)
        else:
            console.print(f"[green]✓ Report saved to: {output_path}[/green]")

    elif output_format == "html":
        reporter = HTMLReporter()
        output = reporter.generate(result, output_path)
        if not output_path:
            console.print(output)
        else:
            console.print(f"[green]✓ Report saved to: {output_path}[/green]")

    else:
        _console_output(result)


def _console_output(result):
    total = result.total_findings
    files = result.total_files

    summary = Table(title="Scan Summary", box=box.ROUNDED)
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="yellow")
    summary.add_row("Files Scanned", str(files))
    summary.add_row("Findings Found", str(total))
    summary.add_row("Scan Duration", f"{result.scan_duration:.2f}s")
    target = getattr(result, "target", "N/A")
    summary.add_row("Target", target)
    console.print(summary)

    if not result.findings:
        console.print("\n[green]✓ No sensitive data found![/green]")
        return

    severity_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_counts: dict = {}
    for f in result.findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        subtype = f.get("subtype", "unknown")
        type_counts[subtype] = type_counts.get(subtype, 0) + 1

    sev_table = Table(title="Findings by Severity", box=box.MINIMAL)
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")

    sev_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            sev_table.add_row(f"[{sev_colors[sev]}]{sev.upper()}[/{sev_colors[sev]}]", str(count))

    type_table = Table(title="Findings by Type", box=box.MINIMAL)
    type_table.add_column("Type", style="bold")
    type_table.add_column("Count", justify="right")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        type_table.add_row(t, str(c))

    console.print("\n")
    console.print(sev_table)
    console.print(type_table)

    findings_table = Table(
        title=f"Findings ({total} total)",
        box=box.SQUARE,
        show_lines=True,
    )
    findings_table.add_column("#", style="dim", width=4, no_wrap=True)
    findings_table.add_column("Severity", style="bold", width=10, no_wrap=True)
    findings_table.add_column("Type", style="cyan", width=14)
    findings_table.add_column("Value", width=34)
    findings_table.add_column("Location", width=40)
    findings_table.add_column("Context", width=50)

    sev_colors_map = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}

    for i, f in enumerate(result.findings[:50], 1):
        sev = f.get("severity", "medium")
        color = sev_colors_map.get(sev, "white")
        sev_label = f"[{color}]{sev.upper():<8}[/{color}]"
        findings_table.add_row(
            str(i),
            sev_label,
            f.get("subtype", "?"),
            f.get("value", "")[:34],
            f.get("file_path", "")[:40],
            f.get("context", "")[:50],
        )

    if len(result.findings) > 50:
        findings_table.add_row(
            "...", "...", "...", "...",
            f"[dim]... and {len(result.findings) - 50} more findings[/dim]",
            "",
        )

    console.print("\n")
    console.print(findings_table)


if __name__ == "__main__":
    main()
