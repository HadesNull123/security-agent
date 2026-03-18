"""corscanner — CORS misconfiguration scanner wrapper.

CORScanner is a fast CORS misconfiguration vulnerabilities scanner.
Detects various CORS misconfigurations including reflect_origin, prefix_match,
suffix_match, trust_null, trust_any_subdomain, custom_third_parties.
https://github.com/chenjj/CORScanner

Install: pip install corscanner
Binary: cors / corscanner
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command

logger = logging.getLogger(__name__)


class CORScannerTool(BaseTool):
    name = "corscanner"
    description = (
        "CORS misconfiguration scanner — detects dangerous Access-Control-Allow-Origin patterns. "
        "Checks for reflect_origin, prefix/suffix match, null trust, subdomain trust, "
        "and third-party origin trust misconfigurations."
    )
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: Domain or URL to check for CORS misconfigurations.
        """
        # CORScanner can be run as 'cors' or 'corscanner' pip command
        # or as 'python cors_scan.py' from source
        cmd = ["cors", "-u", target, "-v"]

        # Output to JSON file
        output_file = "/tmp/corscanner_output.json"
        cmd.extend(["-o", output_file])

        # Custom headers (e.g. Cookie)
        if headers := kwargs.get("headers"):
            cmd.extend(["-d", headers])

        # Thread count
        threads = kwargs.get("threads", 50)
        cmd.extend(["-t", str(threads)])

        returncode, stdout, stderr = await run_command(cmd)

        # If 'cors' binary not found, try 'corscanner'
        if returncode != 0 and ("not found" in (stderr or "").lower() or "No such file" in (stderr or "")):
            cmd[0] = "corscanner"
            returncode, stdout, stderr = await run_command(cmd)

        # Parse results
        findings = []

        # Try JSON output file
        try:
            with open(output_file, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    findings.append(self._parse_cors_finding(entry))
            elif isinstance(data, dict):
                if "results" in data:
                    for entry in data["results"]:
                        findings.append(self._parse_cors_finding(entry))
                else:
                    findings.append(self._parse_cors_finding(data))
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Fallback: parse stdout for CORS findings
        if not findings and stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if any(t in line.lower() for t in [
                    "reflect_origin", "prefix_match", "suffix_match",
                    "trust_null", "trust_any_subdomain", "custom_third",
                    "cors misconfiguration", "vulnerable"
                ]):
                    findings.append({
                        "url": target,
                        "type": line,
                        "severity": self._map_severity(line),
                        "description": f"CORS misconfiguration: {line}",
                    })

        if returncode != 0 and not findings and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"corscanner exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "findings": findings,
                "count": len(findings),
                "cors_issues_found": len(findings) > 0,
            },
            raw_output=stdout[-5000:] if stdout else "",
            command_used=" ".join(cmd),
        )

    @staticmethod
    def _parse_cors_finding(entry: dict) -> dict:
        """Parse a single CORScanner result entry."""
        misconfig_type = entry.get("type", "unknown")
        credentials = entry.get("credentials", "false")

        severity = CORScannerTool._map_severity(misconfig_type, credentials)

        return {
            "url": entry.get("url", ""),
            "type": misconfig_type,
            "origin": entry.get("origin", ""),
            "credentials": credentials,
            "status_code": entry.get("status_code", 0),
            "severity": severity,
            "description": f"CORS {misconfig_type}: origin={entry.get('origin', '?')}, credentials={credentials}",
        }

    @staticmethod
    def _map_severity(misconfig_type: str, credentials: str = "false") -> str:
        """Map CORS misconfiguration type to severity."""
        misconfig_type = misconfig_type.lower()
        cred = credentials.lower() == "true"

        # reflect_origin with credentials = critical (full account takeover possible)
        if "reflect_origin" in misconfig_type and cred:
            return "critical"
        if "reflect_origin" in misconfig_type:
            return "high"
        if "trust_null" in misconfig_type:
            return "high"
        if "prefix_match" in misconfig_type:
            return "medium"
        if "suffix_match" in misconfig_type:
            return "medium"
        if "trust_any_subdomain" in misconfig_type:
            return "medium"
        if "custom_third" in misconfig_type:
            return "low"
        return "medium"
