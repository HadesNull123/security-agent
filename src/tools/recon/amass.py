"""Amass - Comprehensive subdomain enumeration tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command


class AmassTool(BaseTool):
    name = "amass"
    description = "Comprehensive subdomain enumeration using multiple data sources and techniques"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["amass", "enum", "-d", target, "-json", "/dev/stdout"]

        # Passive only (safer)
        if kwargs.get("passive", True):
            cmd.append("-passive")

        # Timeout
        if timeout_min := kwargs.get("timeout_minutes"):
            cmd.extend(["-timeout", str(timeout_min)])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"amass exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        from src.tools import parse_json_lines
        results = parse_json_lines(stdout)
        subdomains = list({r.get("name", "") for r in results if r.get("name")})

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "subdomains": sorted(subdomains),
                "count": len(subdomains),
            },
            raw_output=stdout[:10000],
            command_used=" ".join(cmd),
        )
