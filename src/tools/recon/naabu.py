"""Naabu - Fast port scanner tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class NaabuTool(BaseTool):
    name = "naabu"
    description = "Fast port scanning to discover open ports on target hosts"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["naabu", "-host", target, "-json", "-silent"]

        # Port specification
        if ports := kwargs.get("ports"):
            cmd.extend(["-p", ports])  # e.g. "80,443,8080" or "1-1000"
        else:
            cmd.extend(["-top-ports", kwargs.get("top_ports", "100")])

        # Rate limit
        if rate := kwargs.get("rate"):
            cmd.extend(["-rate", str(rate)])

        # Scan type
        if scan_type := kwargs.get("scan_type"):  # s, c
            cmd.extend(["-scan-type", scan_type])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"naabu exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        ports_found = []
        for r in results:
            ports_found.append({
                "host": r.get("host", r.get("ip", "")),
                "port": r.get("port", 0),
                "protocol": r.get("protocol", "tcp"),
            })

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "open_ports": ports_found,
                "count": len(ports_found),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
