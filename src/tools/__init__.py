"""
Base tool class and utilities for all security tool wrappers.
Provides a consistent interface for CLI tool execution with
timeout management, output parsing, and error handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from src.core.config import ScanPhase
from src.core.models import ToolExecution

logger = logging.getLogger(__name__)


class ToolResult(BaseModel):
    """Standardized result from any tool execution."""
    tool_name: str
    success: bool
    data: dict[str, Any] = {}
    raw_output: str = ""
    error: str = ""
    execution_time: float = 0.0
    command_used: str = ""

    def summary(self, max_length: int = 2000) -> str:
        """Return a token-efficient summary for LLM consumption."""
        if not self.success:
            return f"[{self.tool_name}] FAILED: {self.error}"
        # Use structured data if available, otherwise truncate raw output
        if self.data:
            text = json.dumps(self.data, indent=2, default=str)
        else:
            text = self.raw_output
        if len(text) > max_length:
            text = text[:max_length] + f"\n... (truncated, {len(text)} total chars)"
        return f"[{self.tool_name}] SUCCESS ({self.execution_time:.1f}s):\n{text}"


class BaseTool(ABC):
    """
    Abstract base class for all security tool wrappers.

    Subclasses must implement:
        - name: str
        - description: str
        - phase: ScanPhase
        - _run(): The actual tool execution logic

    Attributes:
        binary_name: The actual binary name on disk (may differ from tool name).
                     E.g. name="theHarvester" but binary_name="theHarvester"
    """

    name: str = "base_tool"
    binary_name: str = ""  # Override if binary name differs from self.name
    description: str = "Base security tool"
    phase: ScanPhase = ScanPhase.RECON

    def __init__(self, timeout: int = 300, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries

    @abstractmethod
    async def _run(self, **kwargs: Any) -> ToolResult:
        """Execute the tool. Must be implemented by subclasses."""
        ...

    async def run(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with timeout, error handling, and retry logic."""
        last_result = None
        for attempt in range(1, self.max_retries + 1):
            start = time.time()
            try:
                result = await asyncio.wait_for(
                    self._run(**kwargs),
                    timeout=self.timeout,
                )
                result.execution_time = time.time() - start
                self._save_result(result)
                if result.success:
                    return result
                last_result = result
                # Don't retry if it's a config/auth error
                if "not found" in result.error.lower() or "not configured" in result.error.lower():
                    return result
                if attempt < self.max_retries:
                    logger.warning(f"Tool {self.name} attempt {attempt} failed: {result.error}. Retrying...")
                    await asyncio.sleep(1)
            except asyncio.TimeoutError:
                last_result = ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Tool timed out after {self.timeout}s (attempt {attempt}/{self.max_retries})",
                    execution_time=time.time() - start,
                )
                if attempt < self.max_retries:
                    logger.warning(f"Tool {self.name} timed out. Retrying...")
            except Exception as e:
                logger.exception(f"Tool {self.name} failed (attempt {attempt})")
                last_result = ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=str(e),
                    execution_time=time.time() - start,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(1)

        return last_result or ToolResult(
            tool_name=self.name, success=False, error="All retry attempts failed"
        )

    def _save_result(self, result: ToolResult) -> None:
        """Auto-save tool result to data/tool_outputs/."""
        try:
            save_tool_output(self.name, result)
        except Exception:
            pass  # Never fail the scan because of output saving

    def is_available(self) -> bool:
        """Check if the tool binary is installed and accessible."""
        check_name = self.binary_name or self.name
        return shutil.which(check_name) is not None

    def to_execution_record(self, result: ToolResult) -> ToolExecution:
        """Convert result to a database execution record."""
        return ToolExecution(
            tool_name=self.name,
            command=result.command_used,
            phase=self.phase,
            status="completed" if result.success else "failed",
            output=result.raw_output[:50000],  # limit stored output
            error=result.error,
            duration_seconds=result.execution_time,
            completed_at=datetime.utcnow(),
        )


async def run_command(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    output_file: str | None = None,
) -> tuple[int, str, str]:
    """
    Run a shell command asynchronously and return (returncode, stdout, stderr).

    Uses a two-phase timeout strategy:
    1. Wait up to `timeout` seconds for the process to complete.
    2. If it times out, check if the process is still producing output.
       Give it an extra grace period (60s) before killing.

    If `output_file` is provided, stdout is ALSO written to that file
    so results are preserved even if the process is killed.
    """
    # Build env with ~/go/bin at the front of PATH
    run_env = env or os.environ.copy()
    go_bin = os.path.expanduser("~/go/bin")
    local_bin = os.path.expanduser("~/.local/bin")
    current_path = run_env.get("PATH", "")
    if go_bin not in current_path:
        run_env["PATH"] = f"{go_bin}:{local_bin}:{current_path}"

    # Only resolve bare command names (no '/' means not already a path)
    if "/" not in cmd[0]:
        resolved = shutil.which(cmd[0], path=run_env.get("PATH"))
        if resolved:
            cmd = [resolved] + cmd[1:]

    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=run_env,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # ─── Grace period: process may be finishing, wait a bit more ──
            logger.warning(
                f"Command '{cmd[0]}' exceeded {timeout}s timeout. "
                f"Granting 60s grace period before terminating..."
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=60,
                )
                logger.info(f"Command '{cmd[0]}' finished during grace period.")
            except asyncio.TimeoutError:
                # Truly timed out — kill it
                logger.warning(f"Command '{cmd[0]}' still running after grace period. Killing.")
                proc.kill()
                # Collect any partial output
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=5
                    )
                except Exception:
                    stdout_bytes, stderr_bytes = b"", b""

                stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

                # Save partial output if output_file specified
                if output_file and stdout_str:
                    _write_output_file(output_file, stdout_str)

                return -1, stdout_str, f"Command timed out after {timeout + 60}s (partial output captured). {stderr_str}"

        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")

        # Save output to file if specified
        if output_file and stdout_str:
            _write_output_file(output_file, stdout_str)

        return (
            proc.returncode or 0,
            stdout_str,
            stderr_str,
        )
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def _write_output_file(filepath: str, content: str) -> None:
    """Write output content to a file, creating directories as needed."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.debug(f"Output saved to: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to save output to {filepath}: {e}")


def parse_json_lines(output: str) -> list[dict]:
    """Parse JSON Lines (JSONL) output from tools like subfinder, naabu, etc."""
    results = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_json_output(output: str) -> dict | list | None:
    """Parse standard JSON output."""
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


# ─── Wordlist Management ─────────────────────────────────────────────

WORDLIST_DIR = os.path.expanduser("~/.secagent/wordlists")
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIR, "common.txt")

# URLs in priority order (fast CDN → GitHub)
WORDLIST_URLS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt",
]


def ensure_wordlist(custom_path: str | None = None) -> str:
    """
    Return a valid wordlist path. Priority:
    1. custom_path (if provided and exists)
    2. System wordlists (/usr/share/...)
    3. Auto-downloaded wordlist (~/.secagent/wordlists/common.txt)
    """
    # User-specified
    if custom_path and os.path.isfile(custom_path):
        return custom_path

    # System wordlists
    for candidate in [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    ]:
        if os.path.isfile(candidate):
            return candidate

    # Auto-download
    if os.path.isfile(DEFAULT_WORDLIST):
        return DEFAULT_WORDLIST

    logger.info(f"Downloading default wordlist to {DEFAULT_WORDLIST}...")
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    import urllib.request
    for url in WORDLIST_URLS:
        try:
            urllib.request.urlretrieve(url, DEFAULT_WORDLIST)
            lines = sum(1 for _ in open(DEFAULT_WORDLIST))
            logger.info(f"✅ Downloaded wordlist: {lines} entries from {url}")
            return DEFAULT_WORDLIST
        except Exception as e:
            logger.warning(f"Failed to download from {url}: {e}")

    # Last resort: create a minimal wordlist
    logger.warning("Could not download wordlist. Creating minimal built-in one.")
    with open(DEFAULT_WORDLIST, "w") as f:
        f.write("\n".join([
            "admin", "login", "api", "dashboard", "config", "backup",
            "test", "dev", "staging", "wp-admin", "wp-login.php",
            ".git", ".env", "robots.txt", "sitemap.xml", "server-status",
            "phpmyadmin", "phpinfo.php", "info.php", "debug", "console",
            "shell", "cmd", "upload", "uploads", "images", "static",
            "assets", "js", "css", "cgi-bin", "bin", "tmp", "temp",
            "old", "new", "bak", ".htaccess", ".htpasswd", "web.config",
        ]))
    return DEFAULT_WORDLIST


# ─── Tool Output Saving ──────────────────────────────────────────────

TOOL_OUTPUT_DIR = os.path.join(".", "data", "tool_outputs")


def save_tool_output(tool_name: str, result: "ToolResult", session_id: str = "") -> str | None:
    """
    Save tool output to data/tool_outputs/<session>/<tool>_<timestamp>.json
    Returns the file path or None if saving failed.
    """
    try:
        output_dir = os.path.join(TOOL_OUTPUT_DIR, session_id or "latest")
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{tool_name}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        output_data = {
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "success": result.success,
            "command": result.command_used,
            "execution_time": result.execution_time,
            "data": result.data,
            "error": result.error,
            "raw_output_preview": (result.raw_output or "")[:5000],
        }

        with open(filepath, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        logger.debug(f"Tool output saved: {filepath}")
        return filepath
    except Exception as e:
        logger.warning(f"Failed to save tool output for {tool_name}: {e}")
        return None
