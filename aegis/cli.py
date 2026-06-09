import asyncio
import sys
import time
from pathlib import Path

import click
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from redteam import AttackResult
from redteam.adapters import AdapterError, get_adapter
from redteam.report import build_report, export_html, export_json, export_markdown
from redteam.runner import load_attacks, run_campaign

console = Console()

_BANNER = """\
[bold red] █████╗ ███████╗ ██████╗ ██╗███████╗[/bold red]
[bold red]██╔══██╗██╔════╝██╔════╝ ██║██╔════╝[/bold red]
[bold red]███████║█████╗  ██║  ███╗██║███████╗[/bold red]
[bold red]██╔══██║██╔══╝  ██║   ██║██║╚════██║[/bold red]
[bold red]██║  ██║███████╗╚██████╔╝██║███████║[/bold red]
[bold red]╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝[/bold red]
[dim]    adversarial testing for language models[/dim]   [bold green]v0.1.0[/bold green]"""


def _print_banner():
    console.print(Panel(
        Align.center(_BANNER),
        border_style="red",
        padding=(0, 2),
    ))
    console.print()


def _detect_format(output_path: str) -> str:
    ext = Path(output_path).suffix.lower()
    return {"json": "json", ".json": "json", ".md": "markdown", ".html": "html"}.get(ext, "json")


def _make_results_table(results: list[AttackResult]) -> Table:
    table = Table(show_header=True, header_style="bold blue", box=None)
    table.add_column("ID", style="dim", width=10)
    table.add_column("Category", width=14)
    table.add_column("Name", width=28)
    table.add_column("Sev", width=8)
    table.add_column("Status", width=8)
    table.add_column("Score", width=6)
    table.add_column("ms", width=7)

    for r in results[-20:]:
        if r.error:
            status = Text("ERR", style="yellow")
        elif r.passed:
            status = Text("PASS ✓", style="green")
        else:
            status = Text("FAIL ✗", style="red")

        sev_color = {"critical": "red", "high": "orange3", "medium": "blue", "low": "dim"}.get(r.attack.severity, "white")
        table.add_row(
            r.attack.id,
            r.attack.category,
            r.attack.name[:28],
            Text(r.attack.severity[:4].upper(), style=sev_color),
            status,
            f"{r.score:.2f}",
            f"{r.latency_ms:.0f}",
        )
    return table


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Aegis — adversarial testing for language models."""
    if ctx.invoked_subcommand is None:
        _print_banner()
        click.echo(ctx.get_help())


@cli.command()
@click.argument("model")
@click.option("--adapter", default="ollama", show_default=True,
              help="ollama|huggingface|openai|anthropic|openai-compatible")
@click.option("--base-url", default=None, help="Base URL for ollama or openai-compatible adapter")
@click.option("--categories", default=None, help="Comma-separated: jailbreaks,injections,bias,hallucination")
@click.option("--severity", default="low", show_default=True,
              help="Min severity: critical|high|medium|low")
@click.option("--concurrency", default=5, show_default=True, help="Parallel requests")
@click.option("--output", default="report.json", show_default=True,
              help="Output path (.json/.md/.html)")
@click.option("--judge", default=None, help="Model to use as LLM judge (same adapter)")
@click.option("--no-dashboard", is_flag=True, help="Skip launching dashboard after run")
@click.option("--quiet", is_flag=True, help="No Rich UI, plain output only")
def run(model, adapter, base_url, categories, severity, concurrency, output, judge, no_dashboard, quiet):
    """Run adversarial attack campaign against a model."""
    from dotenv import load_dotenv
    load_dotenv()

    cat_list = [c.strip() for c in categories.split(",")] if categories else None

    try:
        attacks = load_attacks(categories=cat_list, min_severity=severity)
    except Exception as e:
        console.print(f"[red]Failed to load attacks: {e}[/red]")
        sys.exit(1)

    if not attacks:
        console.print("[yellow]No attacks matched the given filters.[/yellow]")
        sys.exit(0)

    kwargs = {}
    if base_url:
        kwargs["base_url"] = base_url

    try:
        target_adapter = get_adapter(adapter, model, **kwargs)
    except AdapterError as e:
        console.print(f"[red]Adapter error: {e}[/red]")
        sys.exit(1)

    judge_adapter = None
    if judge:
        try:
            judge_adapter = get_adapter(adapter, judge, **kwargs)
        except AdapterError as e:
            console.print(f"[yellow]Warning: Failed to init judge adapter: {e}[/yellow]")

    if not quiet:
        _print_banner()
        console.print(f"  Model: [cyan]{model}[/cyan] via [cyan]{adapter}[/cyan]")
        console.print(f"  Attacks: [cyan]{len(attacks)}[/cyan] | Concurrency: [cyan]{concurrency}[/cyan]")
        console.print(f"  Output: [cyan]{output}[/cyan]\n")

        ping_prompt = "Reply with OK."
        try:
            console.print("[dim]Pinging model...[/dim]", end=" ")
            asyncio.run(target_adapter.complete(ping_prompt))
            console.print("[green]OK[/green]")
        except AdapterError as e:
            console.print(f"[red]FAILED[/red]\n[red]{e}[/red]")
            sys.exit(1)

    results: list[AttackResult] = []

    if quiet:
        start = time.monotonic()
        results = asyncio.run(run_campaign(attacks, target_adapter, concurrency, judge_adapter=judge_adapter))
        duration = time.monotonic() - start
    else:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.completed}/{task.total}"),
            console=console,
        )
        task_id = progress.add_task("Running attacks", total=len(attacks))
        live_table = _make_results_table([])

        layout = Layout()
        layout.split_column(
            Layout(progress, name="progress", size=3),
            Layout(live_table, name="table"),
        )

        def on_progress(completed: int, total: int):
            progress.update(task_id, completed=completed)
            layout["table"].update(_make_results_table(results))

        start = time.monotonic()
        with Live(layout, console=console, refresh_per_second=4):
            results = asyncio.run(
                run_campaign(attacks, target_adapter, concurrency, on_progress, judge_adapter=judge_adapter)
            )
        duration = time.monotonic() - start

    report = build_report(results, model, adapter, duration)

    fmt = _detect_format(output)
    if fmt == "json":
        export_json(report, output)
    elif fmt == "markdown":
        export_markdown(report, output)
    else:
        export_html(report, output)

    if not quiet:
        _print_summary(report)

    if not no_dashboard and not quiet:
        console.print(f"\n[dim]Starting dashboard...[/dim]")
        try:
            from redteam.dashboard import serve
            serve(report)
        except KeyboardInterrupt:
            pass


def _print_summary(report):
    grade_color = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange3", "F": "red"}.get(report.grade, "white")
    console.print(f"\n[bold]Results:[/bold] [{grade_color}]{report.grade}[/{grade_color}] ({report.overall_score:.1f}/100)")

    table = Table(title="Category Scores", show_header=True, header_style="bold blue")
    table.add_column("Category")
    table.add_column("Score")
    table.add_column("Pass")
    table.add_column("Fail")
    table.add_column("Critical Failures")

    for cat_key, cat in report.categories.items():
        pct = cat.score * 100
        score_text = Text(f"{pct:.0f}%", style="green" if pct >= 70 else "yellow" if pct >= 50 else "red")
        table.add_row(
            cat_key.capitalize(),
            score_text,
            str(cat.passed),
            str(cat.failed),
            str(len(cat.critical_failures)),
        )
    console.print(table)

    if report.recommendations:
        console.print("\n[bold yellow]Recommendations:[/bold yellow]")
        for rec in report.recommendations:
            console.print(f"  • {rec}")


@cli.command()
@click.argument("report_file")
@click.option("--port", default=8080, show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
def dashboard(report_file, port, host):
    """Serve a report JSON file in the web dashboard."""
    from pathlib import Path
    from redteam import ReportCard
    from redteam.dashboard import serve

    p = Path(report_file)
    if not p.exists():
        console.print(f"[red]File not found: {report_file}[/red]")
        sys.exit(1)

    try:
        report = ReportCard.model_validate_json(p.read_text())
    except Exception as e:
        console.print(f"[red]Failed to parse report: {e}[/red]")
        sys.exit(1)

    _print_banner()
    console.print(f"[green]Dashboard at http://{host}:{port}[/green]")
    try:
        serve(report, host=host, port=port)
    except KeyboardInterrupt:
        pass


@cli.command("list-attacks")
@click.option("--category", default=None, help="Filter by category")
@click.option("--severity", default=None, help="Filter by severity")
@click.option("--format", "fmt", default="table", show_default=True, help="table|json")
def list_attacks(category, severity, fmt):
    """List all available attacks."""
    cat_list = [category] if category else None
    attacks = load_attacks(categories=cat_list, min_severity=severity)

    if fmt == "json":
        import json as json_mod
        console.print(json_mod.dumps([a.model_dump() for a in attacks], indent=2))
        return

    _print_banner()
    table = Table(title=f"Attacks ({len(attacks)} total)", show_header=True, header_style="bold blue")
    table.add_column("ID", style="dim", width=10)
    table.add_column("Category", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Name", width=32)
    table.add_column("Tags")

    for a in attacks:
        sev_color = {"critical": "red", "high": "orange3", "medium": "blue", "low": "dim"}.get(a.severity, "white")
        table.add_row(
            a.id,
            a.category,
            Text(a.severity.upper(), style=sev_color),
            a.name,
            ", ".join(a.tags[:3]),
        )
    console.print(table)
