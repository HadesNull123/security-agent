"""testssl.sh - SSL/TLS testing tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command
import json


class TestSSLTool(BaseTool):
    name = "testssl"
    binary_name = "testssl.sh"
    description = "Audit SSL/TLS configuration: weak ciphers, expired certificates, protocol vulnerabilities (Heartbleed, POODLE, DROWN)"
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: hostname, URL, or host:port.
        """
        output_file = "/tmp/testssl_output.json"
        cmd = ["testssl.sh", "--jsonfile", output_file, "--quiet"]

        # Fast mode
        if kwargs.get("fast"):
            cmd.append("--fast")

        # Specific checks
        if kwargs.get("vulnerabilities_only"):
            cmd.append("-U")
        if kwargs.get("headers_only"):
            cmd.append("-h")
        if kwargs.get("protocols_only"):
            cmd.append("-p")

        # Sneaky mode (less traces)
        if kwargs.get("sneaky"):
            cmd.append("--sneaky")

        # Timeout
        if connect_timeout := kwargs.get("connect_timeout"):
            cmd.extend(["--connect-timeout", str(connect_timeout)])

        # Target must be last
        cmd.append(target)

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"testssl.sh exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse JSON output
        findings = []
        try:
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        severity = entry.get("severity", "INFO")
                        if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"):
                            findings.append({
                                "id": entry.get("id", ""),
                                "finding": entry.get("finding", ""),
                                "severity": severity,
                                "cve": entry.get("cve", ""),
                                "cwe": entry.get("cwe", ""),
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
                "has_critical": any(f["severity"] == "CRITICAL" for f in findings),
            },
            raw_output=stdout[-5000:] if stdout else "",
            command_used=" ".join(cmd),
        )
