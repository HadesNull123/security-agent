"""Amass - Comprehensive subdomain enumeration tool wrapper.

Supports amass v4 (OWASP Amass) CLI interface.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command


class AmassTool(BaseTool):
    name = "amass"
    description = "Comprehensive subdomain enumeration using multiple data sources and techniques"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        # Amass v4 uses 'amass enum -d target' without -json flag
        # Output to a temp file and read results
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="amass_"
        ) as tmp:
            tmp_path = tmp.name

        try:
            cmd = ["amass", "enum", "-d", target, "-o", tmp_path]

            # Passive only (safer, default)
            mode = kwargs.get("mode", "passive")
            if mode == "passive":
                cmd.append("-passive")

            # Timeout
            if timeout_min := kwargs.get("timeout_minutes"):
                cmd.extend(["-timeout", str(timeout_min)])
            else:
                cmd.extend(["-timeout", "5"])

            returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

            # Read results from output file
            subdomains = []
            if os.path.exists(tmp_path):
                with open(tmp_path, "r") as f:
                    subdomains = [
                        line.strip()
                        for line in f.readlines()
                        if line.strip()
                    ]

            # Also parse stdout for any subdomains
            if stdout:
                for line in stdout.splitlines():
                    line = line.strip()
                    if line and "." in line and not line.startswith("["):
                        if line not in subdomains:
                            subdomains.append(line)

            if returncode != 0 and not subdomains:
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=stderr or f"amass exited with code {returncode}",
                    command_used=" ".join(cmd),
                )

            return ToolResult(
                tool_name=self.name,
                success=True,
                data={
                    "target": target,
                    "subdomains": sorted(set(subdomains)),
                    "count": len(set(subdomains)),
                },
                raw_output=stdout[:10000] if stdout else "\n".join(subdomains[:100]),
                command_used=" ".join(cmd),
            )
        finally:
            # Cleanup temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
