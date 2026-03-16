"""theHarvester - OSINT tool for email, subdomain, IP discovery.

Handles multiple binary name variations since pip may install
as 'theHarvester', 'theharvester', or only as a Python module.
"""

from __future__ import annotations

import shutil
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command


class TheHarvesterTool(BaseTool):
    name = "theHarvester"
    description = "Gather emails, subdomains, IPs, and URLs using multiple OSINT sources"
    phase = ScanPhase.RECON

    def _get_harvester_cmd(self) -> list[str]:
        """Find the correct way to invoke theHarvester."""
        # Try binary names first
        for binary in ["theHarvester", "theharvester", "theHarvester.py"]:
            if shutil.which(binary):
                return [binary]
        # Fallback: invoke as Python module
        return ["python3", "-m", "theHarvester"]

    def is_available(self) -> bool:
        """Check if theHarvester is available (binary or Python module)."""
        # Check binary names
        for binary in ["theHarvester", "theharvester", "theHarvester.py"]:
            if shutil.which(binary):
                return True
        # Check if importable as Python module
        try:
            import importlib
            importlib.import_module("theHarvester")
            return True
        except ImportError:
            return False

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = self._get_harvester_cmd() + [
            "-d", target,
            "-b", kwargs.get("sources", "anubis,hackertarget,crtsh,urlscan"),
        ]

        # Limit results
        if limit := kwargs.get("limit"):
            cmd.extend(["-l", str(limit)])
        else:
            cmd.extend(["-l", "200"])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"theHarvester exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse theHarvester text output
        emails = []
        hosts = []
        ips = []
        section = None
        for line in stdout.splitlines():
            line = line.strip()
            if "Emails found:" in line:
                section = "emails"
                continue
            elif "Hosts found:" in line:
                section = "hosts"
                continue
            elif "IPs found:" in line:
                section = "ips"
                continue
            elif line.startswith("[*]") or line.startswith("---"):
                continue

            if section == "emails" and "@" in line:
                emails.append(line)
            elif section == "hosts" and line:
                hosts.append(line)
            elif section == "ips" and line:
                ips.append(line)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "emails": emails,
                "hosts": hosts,
                "ips": ips,
            },
            raw_output=stdout[:10000],
            command_used=" ".join(cmd),
        )
