"""Nuclei - Template-based vulnerability scanner tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class NucleiTool(BaseTool):
    name = "nuclei"
    description = (
        "Scan targets for vulnerabilities using YAML-based templates. "
        "Supports scanning for CVEs, misconfigurations, default credentials, exposed panels, and more."
    )
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["nuclei", "-u", target, "-json", "-silent"]

        # Template selection
        if templates := kwargs.get("templates"):
            cmd.extend(["-t", templates])  # specific template path or directory
        if tags := kwargs.get("tags"):
            cmd.extend(["-tags", tags])  # e.g. "cve,sqli,xss"
        if severity := kwargs.get("severity"):
            cmd.extend(["-severity", severity])  # critical,high,medium,low,info
        if exclude_tags := kwargs.get("exclude_tags"):
            cmd.extend(["-etags", exclude_tags])

        # Template IDs
        if template_ids := kwargs.get("template_ids"):
            cmd.extend(["-id", template_ids])

        # Rate control
        if rate_limit := kwargs.get("rate_limit"):
            cmd.extend(["-rl", str(rate_limit)])
        if concurrency := kwargs.get("concurrency"):
            cmd.extend(["-c", str(concurrency)])

        # Custom headers
        if headers := kwargs.get("headers"):
            for h in headers:
                cmd.extend(["-H", h])

        # Proxy
        if proxy := kwargs.get("proxy"):
            cmd.extend(["-proxy", proxy])

        # Automatic scan (use all templates)
        if kwargs.get("automatic", False):
            cmd.extend(["-as"])  # automatic scan

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"nuclei exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        findings = []
        for r in results:
            info = r.get("info", {})
            findings.append({
                "template_id": r.get("template-id", r.get("templateID", "")),
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "description": info.get("description", ""),
                "tags": info.get("tags", []),
                "reference": info.get("reference", []),
                "matched_at": r.get("matched-at", r.get("matched", "")),
                "matcher_name": r.get("matcher-name", ""),
                "extracted_results": r.get("extracted-results", []),
                "curl_command": r.get("curl-command", ""),
                "type": r.get("type", ""),
                "host": r.get("host", ""),
                "url": r.get("url", r.get("matched-at", "")),
                "ip": r.get("ip", ""),
                "classification": info.get("classification", {}),
            })

        # Aggregate severity counts
        severity_map: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_map[sev] = severity_map.get(sev, 0) + 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "findings": findings,
                "count": len(findings),
                "severity_summary": severity_map,
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
