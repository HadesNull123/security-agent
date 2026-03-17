"""Subfinder - Fast subdomain discovery tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class SubfinderTool(BaseTool):
    name = "subfinder"
    description = "Discover subdomains for a given domain using multiple passive sources"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["subfinder", "-d", target, "-json", "-silent"]

        # Optional: specific sources
        if sources := kwargs.get("sources"):
            cmd.extend(["-sources", sources])

        # Optional: rate limit
        if rate_limit := kwargs.get("rate_limit"):
            cmd.extend(["-rl", str(rate_limit)])

        returncode, stdout, stderr = await run_command(cmd)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"subfinder exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        subdomains = list({r.get("host", "") for r in results if r.get("host")})

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "subdomains": sorted(subdomains),
                "count": len(subdomains),
                "sources": list({r.get("source", "") for r in results}),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
