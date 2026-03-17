"""
Console UI — Rich terminal interface for real-time scan progress.

Provides a live-updating dashboard showing:
- Current phase with progress indicator
- Multi-panel grid: each tool gets its own output box
- Findings discovered so far
- Token usage and elapsed time

Design: All components are terminal-width-aware to prevent table overflow.
"""

from __future__ import annotations

import math
import os
import time
from collections import deque
from datetime import datetime
from typing import Any

from rich.columns import Columns
from rich.console import Console, Group
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
    "recon": {"icon": "🔍", "label": "RECON", "color": "cyan", "order": 1},
    "scanning": {"icon": "🛡️", "label": "SCAN", "color": "yellow", "order": 2},
    "analysis": {"icon": "🧠", "label": "ANALY", "color": "magenta", "order": 3},
    "exploitation": {"icon": "⚔️", "label": "EXPLT", "color": "red", "order": 4},
    "verification": {"icon": "✅", "label": "VERIF", "color": "bright_cyan", "order": 5},
    "reporting": {"icon": "📝", "label": "REPRT", "color": "green", "order": 6},
}

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

# Max output lines per tool panel
TOOL_LOG_LINES = 5


def _term_width() -> int:
    """Get terminal width, with a sensible minimum."""
    try:
        return max(os.get_terminal_size().columns, 60)
    except OSError:
        return 100


class ScanUI:
    """
    Real-time terminal UI for scan progress.

    Features:
    - Multi-panel grid: each tool gets its own output box
    - Real-time tool output streaming
    - Phase progress bar
    - Findings summary

    Usage:
        ui = ScanUI(targets=["example.com"], mode="normal")
        ui.start()

        ui.set_phase("recon")
        ui.register_phase_tools(["subfinder", "naabu", "katana", "httpx"])
        ui.tool_start("subfinder")
        ui.tool_output("subfinder", "Found: api.example.com")
        ui.tool_complete("subfinder", success=True, result_summary="42 subdomains")

        ui.stop()
    """

    def __init__(self, targets: list[str], mode: str = "normal"):
        self.targets = targets
        self.mode = mode
        self.start_time = time.time()

        # State
        self.current_phase: str = ""
        self.completed_phases: list[str] = []
        self.tool_status: dict[str, dict[str, Any]] = {}
        self.active_tool: str | None = None
        self.findings_summary: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        self.total_findings: int = 0
        self.tokens_used: int = 0
        self.log_messages: list[str] = []
        self.max_log_lines = 5

        # Per-tool output lines for multi-panel display
        self.tool_outputs: dict[str, deque[str]] = {}
        self.phase_tools: list[str] = []

        # Rich components
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=15),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        self._phase_task = self._progress.add_task("Initializing...", total=6)
        self._live: Live | None = None

    def start(self) -> None:
        """Start the live display."""
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            transient=True,
            vertical_overflow="crop",
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

        # Reset phase-specific state
        self.phase_tools = []
        self.tool_outputs.clear()
        self.tool_status.clear()

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

    def register_phase_tools(self, tool_names: list[str]) -> None:
        """Register the list of available tools for the current phase."""
        self.phase_tools = tool_names
        for name in tool_names:
            if name not in self.tool_outputs:
                self.tool_outputs[name] = deque(maxlen=TOOL_LOG_LINES)
                self.tool_status[name] = {
                    "status": "waiting",
                    "start_time": 0,
                    "summary": "",
                }
        self._update()

    # ── Tool Management ─────────────────────────────────────

    def tool_start(self, tool_name: str) -> None:
        """Mark a tool as started."""
        self.active_tool = tool_name
        if tool_name not in self.tool_outputs:
            self.tool_outputs[tool_name] = deque(maxlen=TOOL_LOG_LINES)
        if tool_name not in self.phase_tools:
            self.phase_tools.append(tool_name)

        self.tool_status[tool_name] = {
            "status": "running",
            "start_time": time.time(),
            "summary": "",
        }
        self.tool_outputs[tool_name].append("[yellow]▶ Starting...[/yellow]")
        self.log(f"🔧 Running: {tool_name}")
        self._update()

    def tool_output(self, tool_name: str, line: str) -> None:
        """Add a line of output to a tool's panel."""
        if tool_name not in self.tool_outputs:
            self.tool_outputs[tool_name] = deque(maxlen=TOOL_LOG_LINES)

        # Truncate long lines based on available panel width
        tw = _term_width()
        max_line = max(tw // 3 - 8, 30)  # Panel is ~1/3 of terminal width minus borders
        if len(line) > max_line:
            line = line[:max_line - 3] + "..."
        self.tool_outputs[tool_name].append(line)
        self._update()

    def tool_complete(self, tool_name: str, success: bool = True, result_summary: str = "") -> None:
        """Mark a tool as completed."""
        if tool_name in self.tool_status:
            elapsed = time.time() - self.tool_status[tool_name].get("start_time", time.time())
            self.tool_status[tool_name].update({
                "status": "done" if success else "failed",
                "elapsed": elapsed,
                "summary": result_summary[:60],
            })
        if self.active_tool == tool_name:
            self.active_tool = None

        if tool_name in self.tool_outputs:
            filtered = deque(
                (line for line in self.tool_outputs[tool_name]
                 if "Starting..." not in line),
                maxlen=TOOL_LOG_LINES,
            )
            self.tool_outputs[tool_name] = filtered

            status_icon = "✅" if success else "❌"
            elapsed = self.tool_status.get(tool_name, {}).get("elapsed", 0)
            self.tool_outputs[tool_name].append(
                f"[{'green' if success else 'red'}]{status_icon} Done ({elapsed:.1f}s) {result_summary[:40]}[/]"
            )

        status_icon = "✅" if success else "❌"
        self.log(f"{status_icon} {tool_name}: {result_summary[:40]}")
        self._update()

    # ── Findings ────────────────────────────────────────────

    def add_finding(self, severity: str, title: str) -> None:
        """Register a new finding."""
        sev = severity.lower()
        if sev in self.findings_summary:
            self.findings_summary[sev] += 1
        self.total_findings += 1
        self.log(f"🚨 [{sev.upper()}] {title[:40]}")
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
        self.log_messages.append(f"[dim]{timestamp}[/dim] {message[:80]}")
        if len(self.log_messages) > self.max_log_lines:
            self.log_messages = self.log_messages[-self.max_log_lines:]

    # ── Layout Building ─────────────────────────────────────

    def _build_layout(self) -> Panel:
        """Build the complete dashboard layout. All widths adapt to terminal."""
        elements = [
            self._build_header(),
            self._build_phase_progress(),
            self._build_tools_grid(),
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

    def _build_header(self) -> Table:
        """Build header with target and mode info — uses a table to prevent overflow."""
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)

        # Truncate long target strings
        tw = _term_width()
        max_target = max(tw - 50, 20)
        target_str = ", ".join(self.targets[:2])
        if len(self.targets) > 2:
            target_str += f" (+{len(self.targets) - 2})"
        if len(target_str) > max_target:
            target_str = target_str[:max_target - 3] + "..."

        tbl = Table(show_header=False, show_edge=False, box=None, pad_edge=False, expand=True)
        tbl.add_column(ratio=5, no_wrap=True, overflow="ellipsis")
        tbl.add_column(ratio=1, no_wrap=True, justify="right")
        tbl.add_row(
            f"🎯 [bold]Target:[/bold] [cyan]{target_str}[/cyan]  │  📋 [bold]{self.mode.upper()}[/bold]",
            f"⏱️ {mins:02d}:{secs:02d}  🔤 ~{self.tokens_used:,}",
        )
        return tbl

    def _build_phase_progress(self) -> Panel:
        """Build phase progress bar — fits all phases on one line using short labels."""
        tw = _term_width()
        # Calculate how much space each phase gets
        n_phases = len(PHASE_INFO)
        # Use just icons + short label, no arrows if terminal is narrow
        use_arrows = tw > 80

        phase_line = Text()
        for i, (name, info) in enumerate(PHASE_INFO.items()):
            icon = info["icon"]
            label = info["label"][:4]  # Max 4 chars

            if name in self.completed_phases:
                phase_line.append(f"✅{label}", style="green")
            elif name == self.current_phase:
                phase_line.append(f"▶{label}", style=f"bold {info['color']}")
            else:
                phase_line.append(f"○{label}", style="dim")

            if i < n_phases - 1:
                if use_arrows:
                    phase_line.append("→", style="dim")
                else:
                    phase_line.append(" ", style="dim")

        return Panel(phase_line, title="Progress", border_style="blue", height=3)

    def _build_tools_grid(self) -> Panel:
        """
        Build multi-panel grid. Panel width adapts to terminal.
        Columns: 2 for narrow terminals, 3 for wider ones.
        """
        tools_to_show = self.phase_tools if self.phase_tools else list(self.tool_status.keys())

        if not tools_to_show:
            return Panel(
                Text("Waiting for tools...", style="dim"),
                title="🔧 Tools",
                border_style="dim",
                height=4,
            )

        tw = _term_width()
        # Decide columns count based on terminal width
        if tw >= 140:
            n_cols = 4
        elif tw >= 100:
            n_cols = 3
        elif tw >= 70:
            n_cols = 2
        else:
            n_cols = 1

        # Panel width = terminal / n_cols minus outer panel borders (~6 chars)
        panel_w = max((tw - 6) // n_cols, 25)
        # Line truncation inside panels
        max_line_len = panel_w - 4  # 4 for panel borders

        panels = []
        for name in tools_to_show:
            status_info = self.tool_status.get(name, {"status": "waiting"})
            status = status_info.get("status", "waiting")

            if status == "running":
                border = "bold yellow"
                status_icon = "⏳"
                elapsed = time.time() - status_info.get("start_time", time.time())
                title_extra = f" {elapsed:.0f}s"
            elif status == "done":
                border = "green"
                status_icon = "✅"
                title_extra = f" {status_info.get('elapsed', 0):.1f}s"
            elif status == "failed":
                border = "red"
                status_icon = "❌"
                title_extra = ""
            else:
                border = "dim"
                status_icon = "○"
                title_extra = ""

            output_lines = list(self.tool_outputs.get(name, []))
            if not output_lines:
                if status == "waiting":
                    output_lines = ["[dim]Waiting...[/dim]"]
                elif status == "running":
                    output_lines = ["[yellow]Running...[/yellow]"]

            # Truncate each line to fit panel
            truncated = []
            for line in output_lines[:TOOL_LOG_LINES]:
                # Strip Rich markup for length calc, but keep markup in output
                plain = Text.from_markup(line).plain if "[" in line else line
                if len(plain) > max_line_len:
                    # Simple truncation (may break some markup, but safer)
                    truncated.append(line[:max_line_len - 3] + "...")
                else:
                    truncated.append(line)

            # Pad to fixed height
            while len(truncated) < TOOL_LOG_LINES:
                truncated.append("")

            content = "\n".join(truncated)

            # Truncate tool name for title
            display_name = name[:panel_w - 12] if len(name) > panel_w - 12 else name

            panel = Panel(
                content,
                title=f"{status_icon} [bold]{display_name}[/bold]{title_extra}",
                border_style=border,
                width=panel_w,
                height=TOOL_LOG_LINES + 2,
            )
            panels.append(panel)

        grid = Columns(panels, equal=False, expand=True)

        return Panel(
            grid,
            title=f"🔧 Tools ({len(tools_to_show)})",
            border_style="blue",
        )

    def _build_findings_bar(self) -> Panel:
        """Build findings summary — uses a compact table layout."""
        tbl = Table(show_header=False, show_edge=False, box=None, pad_edge=False, expand=True)
        tbl.add_column(no_wrap=True, width=12)
        for _ in range(5):
            tbl.add_column(no_wrap=True, width=8)

        # Build styled cells
        cells = [f"[bold]Total: {self.total_findings}[/bold]"]
        for sev, count in self.findings_summary.items():
            color = SEVERITY_COLORS.get(sev, "white")
            short = sev[:4].upper()  # CRIT, HIGH, MEDI, LOW, INFO
            cells.append(f"[{color}]{short}:{count}[/{color}]")

        tbl.add_row(*cells)
        return Panel(tbl, title="🚨 Findings", border_style="red", height=3)

    def _build_activity_log(self) -> Panel:
        """Build scrolling activity log."""
        if self.log_messages:
            log_text = "\n".join(self.log_messages)
        else:
            log_text = "[dim]Waiting for activity...[/dim]"
        return Panel(log_text, title="Log", border_style="dim", height=self.max_log_lines + 2)

    def _build_footer(self) -> Text:
        """Build footer."""
        footer = Text()
        footer.append("Ctrl+C to abort", style="dim italic")
        return footer
