"""dnsx - DNS resolution and enumeration tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class DnsxTool(BaseTool):
    name = "dnsx"
    description = "Resolve and validate subdomains via DNS, query multiple record types, detect CDN/ASN"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target can be a single host/domain or a file path prefixed with '@'.
        """
        cmd = ["dnsx", "-json", "-silent"]

        # Input: write single target to a temp file since run_command
        # doesn't support stdin piping
        import tempfile, os
        tmp_input = None
        if target.startswith("@"):
            cmd.extend(["-l", target[1:]])
        else:
            tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp_input.write(target + "\n")
            tmp_input.close()
            cmd.extend(["-l", tmp_input.name])

        # Record types
        record_types = kwargs.get("record_types", ["a"])
        for rt in record_types:
            cmd.append(f"-{rt}")

        # Response display
        cmd.append("-resp")

        # CDN detection
        if kwargs.get("cdn"):
            cmd.append("-cdn")

        # ASN detection
        if kwargs.get("asn"):
            cmd.append("-asn")

        # Threads
        if threads := kwargs.get("threads"):
            cmd.extend(["-t", str(threads)])

        # Rate limit
        if rate_limit := kwargs.get("rate_limit"):
            cmd.extend(["-rl", str(rate_limit)])

        try:
            returncode, stdout, stderr = await run_command(cmd)
        finally:
            if tmp_input and os.path.exists(tmp_input.name):
                os.unlink(tmp_input.name)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"dnsx exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        resolved = []
        for r in results:
            resolved.append({
                "host": r.get("host", ""),
                "a": r.get("a", []),
                "aaaa": r.get("aaaa", []),
                "cname": r.get("cname", []),
                "mx": r.get("mx", []),
                "ns": r.get("ns", []),
                "txt": r.get("txt", []),
                "cdn": r.get("cdn-name", ""),
                "asn": r.get("asn", ""),
                "status_code": r.get("status_code", ""),
            })

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "resolved": resolved,
                "count": len(resolved),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
