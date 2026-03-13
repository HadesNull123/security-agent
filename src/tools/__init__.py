"""
Base tool class and utilities for all security tool wrappers.
Provides a consistent interface for CLI tool execution with
timeout management, output parsing, and error handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
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
) -> tuple[int, str, str]:
    """
    Run a shell command asynchronously and return (returncode, stdout, stderr).
    Resolves the binary path via shutil.which to avoid name conflicts
    (e.g. Python httpx CLI vs Go httpx tool).
    """
    # Resolve absolute path of binary to avoid name conflicts
    resolved = shutil.which(cmd[0])
    if resolved:
        cmd = [resolved] + cmd[1:]

    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


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
