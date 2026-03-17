"""Naabu - Fast port scanner tool wrapper."""

from __future__ import annotations
import logging
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines

logger = logging.getLogger(__name__)


class NaabuTool(BaseTool):
    name = "naabu"
    description = "Fast port scanning to discover open ports on target hosts"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["naabu", "-host", target, "-json", "-silent"]

        # Port specification — default top 100
        if ports := kwargs.get("ports"):
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["-top-ports", kwargs.get("top_ports", "100")])

        # ★ Use CONNECT scan (no root/sudo needed, works everywhere)
        cmd.extend(["-scan-type", "c"])

        # Rate limit
        rate = kwargs.get("rate", 1000)
        cmd.extend(["-rate", str(rate)])

        # Per-host timeout in ms
        cmd.extend(["-timeout", "5000"])

        returncode, stdout, stderr = await run_command(cmd)

        # Log stderr for debugging
        if stderr:
            logger.debug(f"naabu stderr: {stderr[:500]}")

        # Parse results even if exit code is non-zero
        # naabu often returns exit code 1 with partial results
        results = parse_json_lines(stdout) if stdout else []
        ports_found = []
        for r in results:
            ports_found.append({
                "host": r.get("host", r.get("ip", "")),
                "port": r.get("port", 0),
                "protocol": r.get("protocol", "tcp"),
            })

        # If we got results, consider it a success regardless of exit code
        if ports_found:
            return ToolResult(
                tool_name=self.name,
                success=True,
                data={
                    "target": target,
                    "ports": ports_found,
                    "count": len(ports_found),
                },
                raw_output=stdout,
                command_used=" ".join(cmd),
            )

        # No results — treat as failure only if exit code is non-zero
        if returncode != 0:
            error_msg = stderr[:500] if stderr else f"naabu exited with code {returncode}"
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=error_msg,
                command_used=" ".join(cmd),
            )

        # Clean exit, no ports found
        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"target": target, "ports": [], "count": 0},
            raw_output="No open ports found",
            command_used=" ".join(cmd),
        )

