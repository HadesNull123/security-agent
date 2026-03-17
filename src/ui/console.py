"""
Console UI — Rich terminal interface for real-time scan progress.

Layout architecture:
- After scan confirmation → clear screen
- Dashboard draws at TOP of screen (FIXED position using ANSI scroll regions)
- All tool output, JSON, logs scroll BELOW the dashboard naturally
- Dashboard redraws in-place without affecting scrolling area

Uses ANSI escape sequences:
- \\033[2J      — Clear screen
- \\033[H       — Move cursor to home (1,1)
- \\033[s / \\033[u — Save/Restore cursor position
- \\033[top;bot r — Set scroll region (content below dashboard scrolls, dashboard stays)
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque
from datetime import datetime
from io import StringIO
from typing import Any

from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Main console for scrolling output
console = Console()

# Phase display data
PHASE_INFO = {
    "recon": {"icon": "🔍", "label": "RECO", "color": "cyan", "order": 1},
    "scanning": {"icon": "🛡️", "label": "SCAN", "color": "yellow", "order": 2},
    "analysis": {"icon": "🧠", "label": "ANAL", "color": "magenta", "order": 3},
    "exploitation": {"icon": "⚔️", "label": "EXPL", "color": "red", "order": 4},
    "verification": {"icon": "✅", "label": "VERI", "color": "bright_cyan", "order": 5},
    "reporting": {"icon": "📝", "label": "REPR", "color": "green", "order": 6},
}

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

# Max lines per tool mini-panel in dashboard
TOOL_LOG_LINES = 3


def _term_width() -> int:
    try:
        return max(os.get_terminal_size().columns, 60)
    except OSError:
        return 100


def _term_height() -> int:
    try:
        return max(os.get_terminal_size().lines, 20)
    except OSError:
        return 40


class ScanUI:
    """
    Real-time terminal UI with fixed dashboard + scrolling logs.

    ┌──────────────────────────────────────────┐
    │ 🎯 Target: example.com  │  ⏱️ 05:30     │  ← FIXED (ANSI scroll region)
    │ ✅RECO→▶SCAN→○ANAL→○EXPL→○VERI→○REPR   │
    │ ┌──────┐ ┌──────┐ ┌──────┐              │
    │ │nuclei│ │ ffuf │ │nikto │  ← Tools     │
    │ └──────┘ └──────┘ └──────┘              │
    │ 🚨 Total:5  CRIT:1 HIGH:2 MED:2        │
    └──────────────────────────────────────────┘
    16:30:01 🔧 Running: subfinder              ← SCROLLING (normal print)
    16:30:05 ✅ subfinder: 42 subdomains
    16:30:08   naabu: {"host":"...","port":80}
    16:30:10 🚨 [HIGH] SQL Injection in /api
    ...
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

        # Per-tool output for dashboard mini-panels
        self.tool_outputs: dict[str, deque[str]] = {}
        self.phase_tools: list[str] = []

        # Dashboard rendering state
        self._dashboard_height = 0
        self._started = False

    # ── Lifecycle ────────────────────────────────────────────

    def start(self) -> None:
        """Clear screen, draw dashboard at top, set scroll region below."""
        self._started = True
        # Clear entire screen and move cursor to home
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        # Initial dashboard render — sets scroll region
        self._redraw_dashboard(initial=True)

    def stop(self) -> None:
        """Reset scroll region and print final summary."""
        if not self._started:
            return
        # Final dashboard update
        self._redraw_dashboard()
        # Reset scroll region to full terminal
        sys.stdout.write("\033[r")
        # Move cursor below everything
        sys.stdout.write(f"\033[{_term_height()};1H\n")
        sys.stdout.flush()
        self._started = False

    # ── Dashboard Rendering (ANSI scroll region) ────────────

    def _redraw_dashboard(self, initial: bool = False) -> None:
        """Render dashboard at top of screen. Scroll region keeps it fixed."""
        tw = _term_width()
        th = _term_height()

        # Render dashboard to string using a temporary Rich Console
        buf = StringIO()
        temp_console = Console(
            file=buf, width=tw,
            force_terminal=True, color_system="256",
        )
        temp_console.print(self._build_dashboard())
        rendered = buf.getvalue()
        new_height = rendered.rstrip('\n').count('\n') + 1

        # Save cursor position
        sys.stdout.write("\033[s")
        # Move to home (top-left)
        sys.stdout.write("\033[H")
        # Write dashboard
        sys.stdout.write(rendered)
        # Clear any leftover lines if new dashboard is shorter
        if new_height < self._dashboard_height:
            for _ in range(self._dashboard_height - new_height):
                sys.stdout.write("\033[K\n")

        self._dashboard_height = max(new_height, 1)

        # Set scroll region: from below dashboard to terminal bottom
        scroll_top = self._dashboard_height + 1
        if scroll_top < th:
            sys.stdout.write(f"\033[{scroll_top};{th}r")

        if initial:
            # First render: place cursor at start of scroll region
            sys.stdout.write(f"\033[{scroll_top};1H")
        else:
            # Subsequent renders: restore cursor to where it was in scroll region
            sys.stdout.write("\033[u")

        sys.stdout.flush()

    def _update(self) -> None:
        """Refresh the dashboard (non-destructive to scroll area)."""
        if self._started:
            try:
                self._redraw_dashboard()
            except Exception:
                pass  # Never crash on UI update

    def _print_below(self, message: str) -> None:
        """Print a message in the scrolling area below the dashboard."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Print normally — cursor is in scroll region, content scrolls naturally
        console.print(f"[dim]{timestamp}[/dim] {message}")

    # ── Phase Management ────────────────────────────────────

    def set_phase(self, phase: str) -> None:
        if self.current_phase and self.current_phase != phase:
            self.completed_phases.append(self.current_phase)
        self.current_phase = phase

        # Reset phase-specific state
        self.phase_tools = []
        self.tool_outputs.clear()
        self.tool_status.clear()

        info = PHASE_INFO.get(phase, {})
        label = info.get("label", phase.upper())
        icon = info.get("icon", "▶")
        self._print_below(f"{'═' * 50}")
        self._print_below(f"{icon} [bold]Phase: {label}[/bold]")
        self._update()

    def phase_complete(self, phase: str) -> None:
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self._update()

    def register_phase_tools(self, tool_names: list[str]) -> None:
        self.phase_tools = tool_names
        for name in tool_names:
            if name not in self.tool_outputs:
                self.tool_outputs[name] = deque(maxlen=TOOL_LOG_LINES)
                self.tool_status[name] = {"status": "waiting", "start_time": 0, "summary": ""}
        self._update()

    # ── Tool Management ─────────────────────────────────────

    def tool_start(self, tool_name: str) -> None:
        self.active_tool = tool_name
        if tool_name not in self.tool_outputs:
            self.tool_outputs[tool_name] = deque(maxlen=TOOL_LOG_LINES)
        if tool_name not in self.phase_tools:
            self.phase_tools.append(tool_name)

        self.tool_status[tool_name] = {
            "status": "running", "start_time": time.time(), "summary": "",
        }
        self.tool_outputs[tool_name].append("[yellow]▶[/yellow]")
        self._print_below(f"🔧 [yellow]Running:[/yellow] [bold]{tool_name}[/bold]")
        self._update()

    def tool_output(self, tool_name: str, line: str) -> None:
        if tool_name not in self.tool_outputs:
            self.tool_outputs[tool_name] = deque(maxlen=TOOL_LOG_LINES)

        # Dashboard mini-panel: truncated
        tw = _term_width()
        max_line = max(tw // 3 - 8, 30)
        short = line[:max_line - 3] + "..." if len(line) > max_line else line
        self.tool_outputs[tool_name].append(short)

        # Scroll area: full output
        self._print_below(f"  [dim]{tool_name}:[/dim] {line[:150]}")
        self._update()

    def tool_complete(self, tool_name: str, success: bool = True, result_summary: str = "") -> None:
        elapsed = 0.0
        if tool_name in self.tool_status:
            elapsed = time.time() - self.tool_status[tool_name].get("start_time", time.time())
            self.tool_status[tool_name].update({
                "status": "done" if success else "failed",
                "elapsed": elapsed,
                "summary": result_summary[:60],
            })
        if self.active_tool == tool_name:
            self.active_tool = None

        # Update dashboard mini-panel
        if tool_name in self.tool_outputs:
            filtered = deque(
                (l for l in self.tool_outputs[tool_name]
                 if "▶" not in l),
                maxlen=TOOL_LOG_LINES,
            )
            self.tool_outputs[tool_name] = filtered
            icon = "✅" if success else "❌"
            color = "green" if success else "red"
            self.tool_outputs[tool_name].append(
                f"[{color}]{icon} {elapsed:.1f}s {result_summary[:25]}[/]"
            )

        # Scroll area
        icon = "✅" if success else "❌"
        color = "green" if success else "red"
        self._print_below(f"{icon} [{color}]{tool_name}[/{color}]: {result_summary[:60]} ({elapsed:.1f}s)")
        self._update()

    # ── Findings ────────────────────────────────────────────

    def add_finding(self, severity: str, title: str) -> None:
        sev = severity.lower()
        if sev in self.findings_summary:
            self.findings_summary[sev] += 1
        self.total_findings += 1
        color = SEVERITY_COLORS.get(sev, "white")
        self._print_below(f"🚨 [{color}][{sev.upper()}][/{color}] {title[:60]}")
        self._update()

    # ── Token Tracking ──────────────────────────────────────

    def update_tokens(self, tokens: int) -> None:
        self.tokens_used = tokens
        self._update()

    # ── Log ─────────────────────────────────────────────────

    def log(self, message: str) -> None:
        self._print_below(message[:100])

    # ═══════════════════════════════════════════════════════
    # Dashboard Components (rendered at top)
    # ═══════════════════════════════════════════════════════

    def _build_dashboard(self) -> Panel:
        """Build compact fixed dashboard."""
        return Panel(
            Group(
                self._build_header(),
                self._build_phase_bar(),
                self._build_tools_grid(),
                self._build_findings_bar(),
            ),
            title="[bold cyan]🛡️ SECURITY AGENT[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _build_header(self) -> Table:
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)

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
            f"🎯 [bold]{target_str}[/bold]  │  📋 [bold]{self.mode.upper()}[/bold]",
            f"⏱️ {mins:02d}:{secs:02d}  🔤 ~{self.tokens_used:,}",
        )
        return tbl

    def _build_phase_bar(self) -> Text:
        tw = _term_width()
        use_arrows = tw > 80
        line = Text()
        for i, (name, info) in enumerate(PHASE_INFO.items()):
            label = info["label"]
            if name in self.completed_phases:
                line.append(f"✅{label}", style="green")
            elif name == self.current_phase:
                line.append(f"▶{label}", style=f"bold {info['color']}")
            else:
                line.append(f"○{label}", style="dim")
            if i < len(PHASE_INFO) - 1:
                line.append("→" if use_arrows else " ", style="dim")
        return line

    def _build_tools_grid(self) -> Panel:
        tools = self.phase_tools or list(self.tool_status.keys())
        if not tools:
            return Panel(Text("Waiting for tools...", style="dim"), title="🔧 Tools", border_style="dim", height=4)

        tw = _term_width()
        n_cols = 4 if tw >= 140 else 3 if tw >= 100 else 2 if tw >= 70 else 1
        panel_w = max((tw - 6) // n_cols, 25)
        max_line_len = panel_w - 4

        panels = []
        for name in tools:
            si = self.tool_status.get(name, {"status": "waiting"})
            status = si.get("status", "waiting")

            if status == "running":
                border, icon = "bold yellow", "⏳"
                extra = f" {time.time() - si.get('start_time', time.time()):.0f}s"
            elif status == "done":
                border, icon = "green", "✅"
                extra = f" {si.get('elapsed', 0):.1f}s"
            elif status == "failed":
                border, icon = "red", "❌"
                extra = ""
            else:
                border, icon = "dim", "○"
                extra = ""

            lines = list(self.tool_outputs.get(name, []))
            if not lines:
                lines = ["[dim]...[/dim]" if status == "waiting" else "[yellow]▶[/yellow]"]

            # Truncate and pad
            display = []
            for ln in lines[-TOOL_LOG_LINES:]:
                plain = Text.from_markup(ln).plain if "[" in ln else ln
                display.append(ln[:max_line_len - 3] + "..." if len(plain) > max_line_len else ln)
            while len(display) < TOOL_LOG_LINES:
                display.append("")

            dn = name[:panel_w - 12] if len(name) > panel_w - 12 else name
            panels.append(Panel(
                "\n".join(display),
                title=f"{icon} [bold]{dn}[/bold]{extra}",
                border_style=border, width=panel_w, height=TOOL_LOG_LINES + 2,
            ))

        return Panel(
            Columns(panels, equal=False, expand=True),
            title=f"🔧 Tools ({len(tools)})",
            border_style="blue",
        )

    def _build_findings_bar(self) -> Table:
        tbl = Table(show_header=False, show_edge=False, box=None, pad_edge=False, expand=True)
        tbl.add_column(no_wrap=True, width=14)
        for _ in range(5):
            tbl.add_column(no_wrap=True, width=8)
        cells = [f"🚨 [bold]Total:{self.total_findings}[/bold]"]
        for sev, count in self.findings_summary.items():
            color = SEVERITY_COLORS.get(sev, "white")
            cells.append(f"[{color}]{sev[:4].upper()}:{count}[/{color}]")
        tbl.add_row(*cells)
        return tbl
