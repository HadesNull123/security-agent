"""dalfox — XSS vulnerability scanner wrapper.

Dalfox (Finder Of XSS) is a powerful open-source XSS scanner focused on automation.
Supports reflected, stored, and DOM-based XSS detection with parameter analysis.
https://github.com/hahwul/dalfox
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command

logger = logging.getLogger(__name__)


class DalfoxTool(BaseTool):
    name = "dalfox"
    description = (
        "XSS vulnerability scanner — detects reflected, stored, and DOM-based XSS. "
        "Supports parameter analysis, blind XSS callbacks, custom payloads, and JSON output."
    )
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: URL to scan for XSS (e.g. http://example.com/page?param=value)
        """
        cmd = ["dalfox", "url", target]

        # Output format — always use JSON for parsing
        cmd.extend(["--format", "json"])

        # Silence banner
        cmd.append("--silence")

        # Blind XSS callback
        if blind_url := kwargs.get("blind_url"):
            cmd.extend(["-b", blind_url])

        # Custom headers
        if headers := kwargs.get("headers"):
            for h in headers.split(";"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", h])

        # Custom cookies
        if cookie := kwargs.get("cookie"):
            cmd.extend(["--cookie", cookie])

        # Specific parameters to test
        if param := kwargs.get("param"):
            cmd.extend(["-p", param])

        # Custom payloads file
        if custom_payload := kwargs.get("custom_payload"):
            cmd.extend(["--custom-payload", custom_payload])

        # Mining options (parameter mining from DOM/dict)
        if kwargs.get("mining_dom", True):
            cmd.append("--mining-dom")
        if kwargs.get("mining_dict", False):
            cmd.append("--mining-dict")

        # Worker count (concurrency)
        workers = kwargs.get("workers", 10)
        cmd.extend(["-w", str(workers)])

        # Timeout per request
        timeout_val = kwargs.get("timeout", 10)
        cmd.extend(["--timeout", str(timeout_val)])

        # Delay between requests (ms)
        if delay := kwargs.get("delay"):
            cmd.extend(["--delay", str(delay)])

        # Follow redirects
        if kwargs.get("follow_redirects", True):
            cmd.append("--follow-redirects")

        # Output file
        output_file = "/tmp/dalfox_output.json"
        cmd.extend(["-o", output_file])

        returncode, stdout, stderr = await run_command(cmd)

        # Parse results
        findings = []

        # Try JSON output file first
        try:
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append({
                            "type": entry.get("type", "unknown"),
                            "poc": entry.get("poc", entry.get("data", "")),
                            "method": entry.get("method", "GET"),
                            "param": entry.get("param", ""),
                            "payload": entry.get("payload", ""),
                            "evidence": entry.get("evidence", ""),
                            "severity": self._map_severity(entry.get("type", "")),
                        })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

        # Fallback: parse stdout for POC lines
        if not findings and stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("[POC]") or line.startswith("[V]"):
                    findings.append({
                        "type": "xss",
                        "poc": line,
                        "severity": "high",
                    })

        if returncode != 0 and not findings and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"dalfox exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "findings": findings,
                "count": len(findings),
                "xss_found": len(findings) > 0,
            },
            raw_output=stdout[-5000:] if stdout else "",
            command_used=" ".join(cmd),
        )

    @staticmethod
    def _map_severity(xss_type: str) -> str:
        """Map dalfox XSS type to severity."""
        xss_type = xss_type.lower()
        if "stored" in xss_type:
            return "critical"
        if "dom" in xss_type:
            return "high"
        if "reflected" in xss_type:
            return "high"
        if "verified" in xss_type:
            return "high"
        return "medium"
