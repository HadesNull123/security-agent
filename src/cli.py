"""
Security Agent CLI - Beautiful command-line interface using Rich and Click.
Supports scan modes (quick/normal/deep), PDF reports, tool management, and single tool execution.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.core.config import Config
from src.agent.engine import SecurityAgent
from src.scanner.installer import ToolInstaller

console = Console()


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True, show_path=verbose)],
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("langchain").setLevel(logging.WARNING)


def print_banner() -> None:
    banner = """
╔═══════════════════════════════════════════════════════╗
║          🛡️  SECURITY AGENT v1.1.0  🛡️               ║
║       AI-Powered Automated Penetration Testing        ║
╚═══════════════════════════════════════════════════════╝
"""
    console.print(Text(banner, style="bold cyan"))


def print_config_summary(config: Config) -> None:
    summary = config.to_summary()

    table = Table(title="⚙️  Configuration", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("LLM Provider", summary["llm_provider"])
    table.add_row("LLM Model", summary["llm_model"])
    table.add_row("Safe Mode", "✅ Enabled" if summary["safe_mode"] else "❌ Disabled")

    console.print(table)

    api_table = Table(title="🔌 External APIs", show_header=True, header_style="bold magenta")
    api_table.add_column("API", style="cyan")
    api_table.add_column("Status", style="green")

    for api, status in summary["external_apis"].items():
        api_table.add_row(api.capitalize(), status)

    console.print(api_table)


@click.group(invoke_without_command=True)
@click.pass_context
@click.option("--env-file", default=".env", help="Path to .env configuration file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def cli(ctx: click.Context, env_file: str, verbose: bool) -> None:
    """🛡️ Security Agent - AI-Powered Automated Penetration Testing"""
    ctx.ensure_object(dict)
    ctx.obj["env_file"] = env_file
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--type", "target_type", default="domain", type=click.Choice(["domain", "ip", "url", "cidr"]))
@click.option("--mode", default="normal", type=click.Choice(["quick", "normal", "deep"]),
              help="Scan mode: quick (link scan), normal (balanced), deep (comprehensive)")
@click.option("--scope", multiple=True, help="Allowed scope (domains/CIDRs)")
@click.option("--no-safe-mode", is_flag=True, help="Disable safe mode (allow exploitation)")
@click.option("--output", "-o", default="./reports", help="Report output directory")
@click.option("--json-output", is_flag=True, help="Also generate JSON report")
@click.option("--pdf", is_flag=True, default=True, help="Generate PDF report (default: enabled)")
@click.option("--no-pdf", is_flag=True, help="Disable PDF report generation")
@click.option("--spec", "-s", type=click.Path(exists=True), default=None,
              help="Project spec file (PDF/JSON/MD/YAML) — AI extracts APIs/params for targeted scanning")
@click.pass_context
def scan(
    ctx: click.Context,
    targets: tuple[str, ...],
    target_type: str,
    mode: str,
    scope: tuple[str, ...],
    no_safe_mode: bool,
    output: str,
    json_output: bool,
    pdf: bool,
    no_pdf: bool,
    spec: str | None,
) -> None:
    """🔍 Run a penetration test. Modes: quick (link scan), normal, deep."""
    print_banner()

    config = Config(env_file=ctx.obj["env_file"])

    if scope:
        config.agent.allowed_scope = list(scope)
    if no_safe_mode:
        config.agent.safe_mode = False
    config.agent.report_output_dir = output

    print_config_summary(config)

    # Show external scanner status
    if config.acunetix.api_url and config.acunetix.api_key:
        console.print("[green]✅ Acunetix: Configured[/green]")
    else:
        console.print("[yellow]⚠️  Acunetix: Not configured (set ACUNETIX_API_URL and ACUNETIX_API_KEY in .env)[/yellow]")
    if config.zap.api_key:
        console.print("[green]✅ OWASP ZAP: Configured[/green]")
    else:
        console.print("[dim]ℹ️  OWASP ZAP: Not configured (optional)[/dim]")

    # Mode description
    mode_desc = {
        "quick": "⚡ QUICK - Fast link-level scan (recon + critical vulns only)",
        "normal": "🔍 NORMAL - Balanced scan (recon + scanning + analysis + exploit)",
        "deep": "🔬 DEEP - Comprehensive (all tools, full port scan, deep crawl)",
    }
    console.print(f"\n📋 Scan Mode: [bold]{mode_desc[mode]}[/bold]")

    console.print(Panel(
        "\n".join(f"  • {t}" for t in targets),
        title="🎯 Targets",
        border_style="red",
    ))

    # Show spec file info if provided
    if spec:
        from src.agent.spec_parser import get_supported_formats

        # ★ MANDATORY: spec analysis requires LLM — check API key
        llm_key_map = {
            "gemini": config.llm.google_api_key,
            "openai": config.llm.openai_api_key,
            "anthropic": config.llm.anthropic_api_key,
            "ollama": True,  # Ollama is local, no key needed
        }
        provider = config.llm.provider.value
        has_key = bool(llm_key_map.get(provider))
        if not has_key:
            console.print(Panel(
                f"[bold red]❌ ERROR: --spec requires a configured LLM provider.[/bold red]\n\n"
                f"Current provider: [cyan]{provider}[/cyan] — but no API key found.\n\n"
                f"Set the API key in your [bold].env[/bold] file:\n"
                f"  • Gemini: [cyan]GOOGLE_API_KEY=your-key[/cyan]\n"
                f"  • OpenAI: [cyan]OPENAI_API_KEY=your-key[/cyan]\n"
                f"  • Anthropic: [cyan]ANTHROPIC_API_KEY=your-key[/cyan]\n\n"
                f"The --spec option uses AI to extract APIs, params, and attack surface\n"
                f"from your project documentation. This REQUIRES a working LLM connection.",
                title="🛑 LLM Required for Spec Analysis",
                border_style="red",
            ))
            raise SystemExit(1)

        console.print(f"\n📄 Project spec: [bold cyan]{spec}[/bold cyan]")
        console.print("   → AI will extract APIs, params, and attack surface from this file")

    # ★ Ask user for scan intensity (affects max_iterations)
    console.print("\n[bold cyan]🔄 Select Scan Intensity:[/bold cyan]")
    console.print("  [1] ⚡ Light (fast, ~10 tool calls per phase)")
    console.print("  [2] 🔍 Medium (balanced, ~20 tool calls per phase)")
    console.print("  [3] 🔬 Heavy (thorough, ~30 tool calls per phase)")
    console.print("  [4] 💀 Maximum (deepest scan, ~50 tool calls per phase)")

    intensity_map = {"1": 10, "2": 20, "3": 30, "4": 50}
    intensity_labels = {"1": "Light", "2": "Medium", "3": "Heavy", "4": "Maximum"}
    intensity_choice = click.prompt(
        "Select",
        type=click.Choice(["1", "2", "3", "4"]),
        default="2",
    )
    scan_intensity = intensity_map[intensity_choice]
    console.print(f"  → Selected: [bold green]{intensity_labels[intensity_choice]}[/bold green] ({scan_intensity} iterations/phase)\n")

    if not click.confirm("\n⚠️  Proceed with the scan?", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        return

    console.print("\n[bold green]Starting scan...[/bold green]\n")

    agent = SecurityAgent(config)
    try:
        # Use manual loop management to properly clean up subprocess transports
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            session = loop.run_until_complete(agent.scan(
                list(targets), target_type, mode=mode,
                scan_intensity=scan_intensity, spec_file=spec,
            ))
        finally:
            # Properly shut down to avoid "Event loop is closed" errors from subprocess __del__
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.run_until_complete(loop.shutdown_default_executor())
            except Exception:
                pass
            loop.close()

        # Print summary
        console.print()
        summary_table = Table(title="📊 Scan Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("Scan Mode", mode.upper())
        summary_table.add_row("Status", session.status.upper())
        summary_table.add_row("Total Findings", str(session.total_findings))
        for sev, count in session.severity_summary.items():
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(sev, "white")
            summary_table.add_row(f"  {sev.upper()}", f"[{color}]{count}[/{color}]")
        summary_table.add_row("Tools Executed", str(len(session.tool_executions)))
        summary_table.add_row("Exploits Attempted", str(len(session.exploit_results)))
        summary_table.add_row("Token Usage", f"~{agent.token_tracker.tokens_used:,}")

        console.print(summary_table)

        # Report paths from agent context
        if report_path := agent.context.get("report_path"):
            console.print(f"\n[green]📝 Report: {report_path}[/green]")
        if pdf_path := agent.context.get("pdf_report_path"):
            console.print(f"[green]📕 PDF: {pdf_path}[/green]")

        if session.status == "partial":
            console.print("[yellow]⚠️ Scan stopped early due to token budget limit.[/yellow]")

    except Exception as e:
        console.print(f"[bold red]❌ Scan failed: {e}[/bold red]")
        if ctx.obj["verbose"]:
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """📊 Show agent status and available tools."""
    print_banner()
    config = Config(env_file=ctx.obj["env_file"])
    print_config_summary(config)

    agent = SecurityAgent(config)
    tools = agent.get_available_tools()

    console.print()
    for category, tool_list in tools.items():
        table = Table(title=f"🔧 {category.upper()} Tools", show_header=False)
        table.add_column("Tool", style="cyan")
        for tool in tool_list:
            table.add_row(tool)
        console.print(table)
        console.print()


@cli.command(name="install-tools")
@click.option("--all", "install_all", is_flag=True, help="Install all missing tools")
@click.argument("tool_names", nargs=-1)
@click.pass_context
def install_tools(ctx: click.Context, install_all: bool, tool_names: tuple[str, ...]) -> None:
    """🔧 Install missing security tools."""
    print_banner()
    installer = ToolInstaller()

    if install_all:
        from src.scanner.installer import TOOL_REGISTRY
        tool_names = tuple(TOOL_REGISTRY.keys())

    if not tool_names:
        # Show status
        status = installer.get_status()
        table = Table(title="🔧 Tool Installation Status", show_header=True, header_style="bold magenta")
        table.add_column("Tool", style="cyan")
        table.add_column("Installed", style="green")
        table.add_column("Method", style="yellow")
        table.add_column("Description")

        for name, info in status.items():
            table.add_row(
                name,
                "✅" if info["installed"] else "❌",
                info["install_method"],
                info["description"],
            )
        console.print(table)
        console.print("\nUse [cyan]secagent install-tools --all[/cyan] to install all missing tools.")
        return

    console.print(f"[cyan]Installing tools: {', '.join(tool_names)}[/cyan]\n")

    async def _install():
        results = await installer.install_all_missing(list(tool_names))
        for tool, (success, msg) in results.items():
            if success:
                console.print(f"  ✅ {tool}: {msg}")
            else:
                console.print(f"  ❌ {tool}: {msg}")
        if not results:
            console.print("  ✅ All specified tools are already installed!")

    asyncio.run(_install())


@cli.command()
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """⚙️  Show current configuration."""
    print_banner()
    config = Config(env_file=ctx.obj["env_file"])
    print_config_summary(config)


@cli.command(name="run-tool")
@click.argument("target")
@click.option("--tool", required=True, help="Tool to run (e.g., subfinder, nuclei)")
@click.option("--args", "tool_args", default="{}", help="Tool arguments as JSON string")
@click.pass_context
def run_tool(ctx: click.Context, target: str, tool: str, tool_args: str) -> None:
    """🔧 Run a single tool directly (for testing)."""
    print_banner()
    config = Config(env_file=ctx.obj["env_file"])

    try:
        args = json.loads(tool_args)
    except json.JSONDecodeError:
        console.print("[red]Invalid JSON for --args[/red]")
        sys.exit(1)

    args["target"] = target

    agent = SecurityAgent(config)
    all_tools = {**agent.recon_tools, **agent.scanner_tools, **agent.exploit_tools}

    if tool not in all_tools:
        console.print(f"[red]Unknown tool: {tool}[/red]")
        console.print(f"Available: {', '.join(all_tools.keys())}")
        sys.exit(1)

    tool_instance = all_tools[tool]

    if not tool_instance.is_available():
        console.print(f"[yellow]⚠️ {tool} is not installed.[/yellow]")
        if click.confirm("Install it now?"):
            asyncio.run(ToolInstaller().install_tool(tool))
        else:
            sys.exit(1)

    console.print(f"[cyan]Running {tool} against {target}...[/cyan]\n")

    result = asyncio.run(tool_instance.run(**args))

    if result.success:
        console.print(Panel(
            json.dumps(result.data, indent=2, default=str),
            title=f"✅ {tool} Results",
            border_style="green",
        ))
    else:
        console.print(Panel(
            result.error,
            title=f"❌ {tool} Failed",
            border_style="red",
        ))


def main() -> None:
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
