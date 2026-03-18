"""crlfuzz — CRLF injection vulnerability scanner wrapper.

CRLFuzz is a fast tool to scan CRLF vulnerability written in Go.
Tests for HTTP response splitting via header injection.
https://github.com/dwisiswant0/crlfuzz
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command

logger = logging.getLogger(__name__)


class CRLFuzzTool(BaseTool):
    name = "crlfuzz"
    description = (
        "CRLF injection scanner — detects HTTP response splitting vulnerabilities. "
        "Tests various CRLF payloads against target URLs to find header injection points."
    )
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: URL to scan for CRLF injection (e.g. http://example.com)
        """
        cmd = ["crlfuzz", "-u", target]

        # Silent mode — only show vulnerable URLs
        cmd.append("-s")

        # Verbose for error details
        if kwargs.get("verbose", False):
            cmd.append("-v")

        # HTTP method
        if method := kwargs.get("method"):
            cmd.extend(["-X", method])

        # POST data
        if data := kwargs.get("data"):
            cmd.extend(["-d", data])

        # Custom headers
        if headers := kwargs.get("headers"):
            for h in headers.split(";"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", h])

        # Concurrency (default 25)
        concurrency = kwargs.get("concurrency", 25)
        cmd.extend(["-c", str(concurrency)])

        # Output file
        output_file = "/tmp/crlfuzz_output.txt"
        cmd.extend(["-o", output_file])

        returncode, stdout, stderr = await run_command(cmd)

        # Parse results — vulnerable URLs
        findings = []

        # Read output file
        try:
            with open(output_file, "r") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        findings.append({
                            "vulnerable_url": url,
                            "type": "crlf_injection",
                            "severity": "medium",
                            "description": f"CRLF injection found: HTTP response splitting via header injection at {url}",
                        })
        except FileNotFoundError:
            pass

        # Fallback: parse stdout (silent mode outputs vulnerable URLs)
        if not findings and stdout:
            for line in stdout.splitlines():
                url = line.strip()
                if url and url.startswith("http"):
                    findings.append({
                        "vulnerable_url": url,
                        "type": "crlf_injection",
                        "severity": "medium",
                        "description": f"CRLF injection found at {url}",
                    })

        if returncode != 0 and not findings and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"crlfuzz exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "findings": findings,
                "count": len(findings),
                "crlf_found": len(findings) > 0,
            },
            raw_output=stdout[-5000:] if stdout else "",
            command_used=" ".join(cmd),
        )
