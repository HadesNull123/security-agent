"""httpx - HTTP probing and technology detection tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class HttpxTool(BaseTool):
    name = "httpx"
    description = "Probe HTTP servers for status, titles, technologies, and response details"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target can be a single host or a file path prefixed with '@'.
        """
        cmd = ["httpx", "-json", "-silent"]

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
