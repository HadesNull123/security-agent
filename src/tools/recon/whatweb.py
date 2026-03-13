"""WhatWeb - Web technology fingerprinting tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_output


class WhatWebTool(BaseTool):
    name = "whatweb"
    description = "Identify web technologies, CMS, frameworks, server software, and plugins"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["whatweb", target, "--log-json=-", "--color=never"]

        # Aggression level
        aggression = kwargs.get("aggression", 1)  # 1=stealthy, 3=aggressive
        cmd.extend(["-a", str(aggression)])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"whatweb exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        from src.tools import parse_json_lines
        results = parse_json_lines(stdout)
        technologies = []
        for r in results:
            plugins = r.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                tech = {"name": plugin_name}
                if isinstance(plugin_data, dict):
                    if version := plugin_data.get("version"):
                        tech["version"] = version[0] if isinstance(version, list) else version
                    if string := plugin_data.get("string"):
                        tech["detail"] = string[0] if isinstance(string, list) else string
                technologies.append(tech)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "url": r.get("target", target) if results else target,
                "http_status": results[0].get("http_status", 0) if results else 0,
                "technologies": technologies,
                "count": len(technologies),
            },
            raw_output=stdout[:5000],
            command_used=" ".join(cmd),
        )
