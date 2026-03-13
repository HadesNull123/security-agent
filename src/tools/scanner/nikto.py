"""nikto - Web server vulnerability scanner wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command
import json


class NiktoTool(BaseTool):
    name = "nikto"
    description = "Scan web servers for outdated software, dangerous files, misconfigurations, and default installations"
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: URL or host to scan.
        """
        cmd = ["nikto", "-h", target, "-nointeractive"]

        # Port
        if port := kwargs.get("port"):
            cmd.extend(["-p", str(port)])

        # Tuning
        if tuning := kwargs.get("tuning"):
            cmd.extend(["-Tuning", tuning])

        # SSL
        if kwargs.get("ssl"):
            cmd.append("-ssl")

        # Output format
        cmd.extend(["-Format", "json", "-o", "/tmp/nikto_output.json"])

        # Evasion
        if evasion := kwargs.get("evasion"):
            cmd.extend(["-evasion", evasion])

        # Max time — default 300s (5 min) to prevent endless scans
        maxtime = kwargs.get("maxtime", 300)
        cmd.extend(["-maxtime", str(maxtime)])

        # Timeout per request — default 10s
        timeout_val = kwargs.get("timeout", 10)
        cmd.extend(["-timeout", str(timeout_val)])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"nikto exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Try to read JSON output
        findings = []
        try:
            with open("/tmp/nikto_output.json", "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    findings.append({
                        "id": v.get("id", ""),
                        "msg": v.get("msg", ""),
                        "method": v.get("method", ""),
                        "url": v.get("url", ""),
                        "references": v.get("references", {}),
                    })
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "findings": findings,
                "count": len(findings),
            },
            raw_output=stdout[-5000:] if stdout else "",
            command_used=" ".join(cmd),
        )
