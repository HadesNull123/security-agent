"""httpx - HTTP probing and technology detection tool wrapper.

IMPORTANT: This wraps ProjectDiscovery's httpx (Go binary), NOT the Python httpx library.
The Python httpx package also installs a CLI called 'httpx' which has completely different
arguments. This module resolves the correct Go binary to avoid conflicts.
"""

from __future__ import annotations
import os
import shutil
import logging
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines

logger = logging.getLogger(__name__)


def _find_go_httpx() -> str:
    """
    Find the ProjectDiscovery httpx (Go) binary, avoiding Python's httpx CLI.

    Search order:
    1. ~/go/bin/httpx (standard Go install location)
    2. 'httpx' in PATH — but only if it's the Go version (has -json flag)
    3. 'pd-httpx' (alternative name used by some package managers)
    """
    # 1. Direct Go bin path
    go_httpx = os.path.expanduser("~/go/bin/httpx")
    if os.path.isfile(go_httpx) and os.access(go_httpx, os.X_OK):
        logger.debug(f"Using Go httpx at: {go_httpx}")
        return go_httpx

    # 2. Check if 'httpx' in PATH is the Go version
    system_httpx = shutil.which("httpx")
    if system_httpx:
        # Go httpx lives in go/bin; Python httpx lives in .local/bin or site-packages
        if "go/bin" in system_httpx or "go/bin" in os.path.realpath(system_httpx):
            logger.debug(f"Using Go httpx from PATH: {system_httpx}")
            return system_httpx

    # 3. Some distros/users install as pd-httpx
    pd_httpx = shutil.which("pd-httpx")
    if pd_httpx:
        logger.debug(f"Using pd-httpx: {pd_httpx}")
        return pd_httpx

    # Fallback — will likely fail if Python httpx is in PATH
    logger.warning(
        "Could not find ProjectDiscovery httpx (Go). "
        "Falling back to 'httpx' which may be the Python httpx CLI. "
        "Install Go httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    )
    return "httpx"


class HttpxTool(BaseTool):
    name = "httpx"
    binary_name = "httpx"
    description = "Probe HTTP servers for status, titles, technologies, and response details"
    phase = ScanPhase.RECON

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self._binary = _find_go_httpx()

    def is_available(self) -> bool:
        """Check if the Go httpx binary is accessible."""
        if self._binary and self._binary != "httpx":
            return os.path.isfile(self._binary) and os.access(self._binary, os.X_OK)
        # Fallback: check if httpx exists at all
        return shutil.which("httpx") is not None

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target can be a single host or a file path prefixed with '@'.
        """
        cmd = [self._binary, "-json", "-silent"]

        # Input
        if target.startswith("@"):
            cmd.extend(["-l", target[1:]])
        else:
            cmd.extend(["-u", target])

        # Probes
        cmd.extend([
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-length",
            "-follow-redirects",
        ])

        # Threads
        if threads := kwargs.get("threads"):
            cmd.extend(["-threads", str(threads)])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            # Detect Python httpx CLI error
            if "Usage: httpx [OPTIONS] URL" in (stderr or ""):
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=(
                        "Wrong httpx binary! Python httpx CLI was called instead of "
                        "ProjectDiscovery httpx (Go). Fix: go install "
                        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
                    ),
                    command_used=" ".join(cmd),
                )
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"httpx exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        hosts = []
        for r in results:
            hosts.append({
                "url": r.get("url", ""),
                "status_code": r.get("status_code", 0),
                "title": r.get("title", ""),
                "technologies": r.get("tech", []),
                "server": r.get("webserver", ""),
                "content_length": r.get("content_length", 0),
                "final_url": r.get("final_url", ""),
                "method": r.get("method", ""),
                "host": r.get("host", ""),
                "port": r.get("port", ""),
                "scheme": r.get("scheme", ""),
            })

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "hosts": hosts,
                "count": len(hosts),
                "technologies_found": list({
                    tech for h in hosts for tech in h.get("technologies", [])
                }),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
