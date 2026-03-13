"""
Console UI — Rich terminal interface for real-time scan progress.

Provides a live-updating dashboard showing:
- Current phase with progress indicator
- Tool execution status (running/completed/failed)
- Findings discovered so far
- Token usage and elapsed time
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()

# Phase display data
PHASE_INFO = {
    "recon": {"icon": "🔍", "label": "RECONNAISSANCE", "color": "cyan", "order": 1},
    "scanning": {"icon": "🛡️", "label": "SCANNING", "color": "yellow", "order": 2},
    "analysis": {"icon": "🧠", "label": "ANALYSIS", "color": "magenta", "order": 3},
    "exploitation": {"icon": "⚔️", "label": "EXPLOITATION", "color": "red", "order": 4},
    "reporting": {"icon": "📝", "label": "REPORTING", "color": "green", "order": 5},
}

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


class ScanUI:
    """
    Real-time terminal UI for scan progress.

    Usage:
        ui = ScanUI(targets=["example.com"], mode="normal")
        ui.start()

        ui.set_phase("recon")
        ui.tool_start("subfinder")
        ui.tool_complete("subfinder", success=True, result_summary="Found 42 subdomains")
        ui.add_finding("critical", "SQL Injection in /login")

        ui.stop()
    """

    def __init__(self, targets: list[str], mode: str = "normal"):
        self.targets = targets
        self.mode = mode
        self.start_time = time.time()

        # State
        self.current_phase: str = ""
        self.completed_phases: list[str] = []
        self.tool_status: dict[str, dict[str, Any]] = {}  # name -> {status, time, summary}
        self.active_tool: str | None = None
        self.findings_summary: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        self.total_findings: int = 0
        self.tokens_used: int = 0
        self.log_messages: list[str] = []
        self.max_log_lines = 8

        # Rich components
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=20),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        self._phase_task = self._progress.add_task("Initializing...", total=5)
        self._live: Live | None = None

    def start(self) -> None:
        """Start the live display."""
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display and print final summary."""
        if self._live:
            self._live.update(self._build_layout())
            self._live.stop()
            self._live = None

    def _update(self) -> None:
        """Refresh the live display."""
        if self._live:
            self._live.update(self._build_layout())

    # ── Phase Management ────────────────────────────────────

    def set_phase(self, phase: str) -> None:
        """Set the current scan phase."""
        if self.current_phase and self.current_phase != phase:
            self.completed_phases.append(self.current_phase)
        self.current_phase = phase

        info = PHASE_INFO.get(phase, {})
        order = info.get("order", 0)
        label = info.get("label", phase.upper())
        icon = info.get("icon", "▶")
        self._progress.update(self._phase_task, completed=order, description=f"{icon} {label}")
        self.log(f"Phase started: {label}")
        self._update()

    def phase_complete(self, phase: str) -> None:
        """Mark a phase as completed."""
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self._update()

    # ── Tool Management ─────────────────────────────────────

    def tool_start(self, tool_name: str) -> None:
        """Mark a tool as started."""
        self.active_tool = tool_name
        self.tool_status[tool_name] = {
            "status": "running",
            "start_time": time.time(),
            "summary": "",
        }
        self.log(f"🔧 Running: {tool_name}")
        self._update()

    def tool_complete(self, tool_name: str, success: bool = True, result_summary: str = "") -> None:
        """Mark a tool as completed."""
        if tool_name in self.tool_status:
            elapsed = time.time() - self.tool_status[tool_name]["start_time"]
            self.tool_status[tool_name].update({
                "status": "done" if success else "failed",
                "elapsed": elapsed,
                "summary": result_summary[:60],
            })
        if self.active_tool == tool_name:
            self.active_tool = None

        status_icon = "✅" if success else "❌"
        self.log(f"{status_icon} {tool_name}: {result_summary[:50]}")
        self._update()

    # ── Findings ────────────────────────────────────────────

    def add_finding(self, severity: str, title: str) -> None:
        """Register a new finding."""
        sev = severity.lower()
        if sev in self.findings_summary:
            self.findings_summary[sev] += 1
        self.total_findings += 1
        self.log(f"🚨 [{sev.upper()}] {title[:50]}")
        self._update()

    # ── Token Tracking ──────────────────────────────────────

    def update_tokens(self, tokens: int) -> None:
        """Update token usage display."""
        self.tokens_used = tokens
        self._update()

    # ── Log ─────────────────────────────────────────────────

    def log(self, message: str) -> None:
        """Add a log message to the activity feed."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_messages.append(f"[dim]{timestamp}[/dim] {message}")
        if len(self.log_messages) > self.max_log_lines:
            self.log_messages = self.log_messages[-self.max_log_lines:]

    # ── Layout Building ─────────────────────────────────────

    def _build_layout(self) -> Panel:
        """Build the complete dashboard layout."""
        elements = [
            self._build_header(),
            self._build_phase_progress(),
            self._build_tools_table(),
            self._build_findings_bar(),
            self._build_activity_log(),
            self._build_footer(),
        ]
        return Panel(
            Group(*elements),
            title="[bold cyan]🛡️ SECURITY AGENT[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _build_header(self) -> Text:
        """Build header with target and mode info."""
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        target_str = ", ".join(self.targets[:3])
        if len(self.targets) > 3:
            target_str += f" (+{len(self.targets) - 3} more)"

        header = Text()
        header.append(f"🎯 Target: ", style="bold")
        header.append(f"{target_str}", style="cyan")
        header.append(f"  │  📋 Mode: ", style="bold")
        header.append(f"{self.mode.upper()}", style="yellow")
        header.append(f"  │  ⏱️ {mins:02d}:{secs:02d}", style="green")
        header.append(f"  │  🔤 ~{self.tokens_used:,} tokens", style="dim")
        return header

    def _build_phase_progress(self) -> Panel:
        """Build phase progress bar."""
        phase_line = Text()
        for name, info in PHASE_INFO.items():
            icon = info["icon"]
            label = info["label"][:5]
            if name in self.completed_phases:
                phase_line.append(f" ✅{label} ", style="green")
            elif name == self.current_phase:
                phase_line.append(f" ▶ {label} ", style=f"bold {info['color']}")
            else:
                phase_line.append(f" ○ {label} ", style="dim")
            phase_line.append("→", style="dim")
        phase_line.append(" 🏁", style="dim")

        return Panel(phase_line, title="Phase Progress", border_style="blue", height=3)

    def _build_tools_table(self) -> Table:
        """Build tools execution table."""
        table = Table(
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=True,
            title="Tool Execution",
        )
        table.add_column("Tool", style="cyan", width=16)
        table.add_column("Status", width=10)
        table.add_column("Time", width=8, justify="right")
        table.add_column("Result", ratio=1)

        # Show last 6 tools executed + active one
        items = list(self.tool_status.items())
        if len(items) > 7:
            items = items[-7:]

        for name, info in items:
            status = info["status"]
            if status == "running":
                status_text = Text("⏳ RUN", style="bold yellow")
                elapsed = time.time() - info["start_time"]
                time_text = f"{elapsed:.0f}s"
            elif status == "done":
                status_text = Text("✅ OK", style="green")
                time_text = f"{info.get('elapsed', 0):.1f}s"
            else:
                status_text = Text("❌ FAIL", style="red")
                time_text = f"{info.get('elapsed', 0):.1f}s"

            table.add_row(name, status_text, time_text, info.get("summary", ""))

        if not items:
            table.add_row("—", Text("WAITING", style="dim"), "—", "No tools executed yet")

        return table

    def _build_findings_bar(self) -> Panel:
        """Build findings summary bar."""
        findings_text = Text()
        findings_text.append(f"Total: {self.total_findings}  │  ", style="bold")
        for sev, count in self.findings_summary.items():
            color = SEVERITY_COLORS.get(sev, "white")
            findings_text.append(f"  {sev.upper()}: ", style="bold")
            findings_text.append(f"{count}", style=color)
        return Panel(findings_text, title="🚨 Findings", border_style="red", height=3)

    def _build_activity_log(self) -> Panel:
        """Build scrolling activity log."""
        if self.log_messages:
            log_text = "\n".join(self.log_messages)
        else:
            log_text = "[dim]Waiting for activity...[/dim]"
        return Panel(log_text, title="Activity Log", border_style="dim", height=self.max_log_lines + 2)

    def _build_footer(self) -> Text:
        """Build footer with instructions."""
        footer = Text()
        footer.append("Press Ctrl+C to abort scan gracefully", style="dim italic")
        return footer
