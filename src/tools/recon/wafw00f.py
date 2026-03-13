"""wafw00f - Web Application Firewall detection tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command


class Wafw00fTool(BaseTool):
    name = "wafw00f"
    description = "Detect Web Application Firewalls (WAF) protecting a target"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        url = target if "://" in target else f"http://{target}"
        cmd = ["wafw00f", url]

        # Check all WAFs (not just first match)
        if kwargs.get("find_all"):
            cmd.append("-a")

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"wafw00f exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse wafw00f output
        waf_detected = False
        waf_name = "None"
        for line in stdout.splitlines():
            line = line.strip()
            if "is behind" in line:
                waf_detected = True
                # Extract WAF name: "The site ... is behind X (Y) WAF"
                parts = line.split("is behind")
                if len(parts) > 1:
                    waf_name = parts[1].strip().rstrip(".")
            elif "No WAF" in line:
                waf_detected = False
                waf_name = "None"

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "waf_detected": waf_detected,
                "waf_name": waf_name,
                "recommendation": (
                    f"WAF detected ({waf_name}). Use lower scan rates and evasion techniques."
                    if waf_detected else
                    "No WAF detected. Standard scanning can proceed."
                ),
            },
            raw_output=stdout[:3000],
            command_used=" ".join(cmd),
        )
