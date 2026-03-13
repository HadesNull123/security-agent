"""ffuf - Fast web fuzzer tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_output, ensure_wordlist


class FfufTool(BaseTool):
    name = "ffuf"
    description = "Fast web fuzzer for directory/file brute-forcing, parameter fuzzing, and virtual host discovery"
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        target: URL with FUZZ keyword, e.g. "http://example.com/FUZZ"
        """
        cmd = ["ffuf", "-u", target, "-o", "/dev/stdout", "-of", "json", "-s"]

        # Wordlist — auto-download if needed
        wordlist = ensure_wordlist(kwargs.get("wordlist"))
        cmd.extend(["-w", wordlist])

        # Filters — default: filter out 404
        has_filter = False
        if mc := kwargs.get("match_codes"):
            cmd.extend(["-mc", mc])
            has_filter = True
        if fc := kwargs.get("filter_codes"):
            cmd.extend(["-fc", fc])
            has_filter = True
        if ms := kwargs.get("match_size"):
            cmd.extend(["-ms", ms])
            has_filter = True
        if fs := kwargs.get("filter_size"):
            cmd.extend(["-fs", fs])
            has_filter = True
        if fw := kwargs.get("filter_words"):
            cmd.extend(["-fw", fw])
            has_filter = True
        if fl := kwargs.get("filter_lines"):
            cmd.extend(["-fl", fl])
            has_filter = True
        if not has_filter:
            cmd.extend(["-fc", "404"])  # ★ filter 404 by default

        # Speed — default 40 threads
        threads = kwargs.get("threads", 40)
        cmd.extend(["-t", str(threads)])
        if rate := kwargs.get("rate"):
            cmd.extend(["-rate", str(rate)])

        # Extensions
        if extensions := kwargs.get("extensions"):
            cmd.extend(["-e", extensions])

        # Method
        if method := kwargs.get("method"):
            cmd.extend(["-X", method])

        # Headers
        if headers := kwargs.get("headers"):
            for h in headers:
                cmd.extend(["-H", h])

        # Recursion
        if kwargs.get("recursion"):
            cmd.extend(["-recursion", "-recursion-depth", str(kwargs.get("recursion_depth", 2))])

        # ★ Performance: timeout per request
        cmd.extend(["-timeout", "10"])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"ffuf exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        parsed = parse_json_output(stdout)
        results_list = []
        if parsed and isinstance(parsed, dict):
            for r in parsed.get("results", []):
                results_list.append({
                    "input": r.get("input", {}).get("FUZZ", ""),
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "content_type": r.get("content-type", ""),
                    "redirect_location": r.get("redirectlocation", ""),
                })

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "results": results_list,
                "count": len(results_list),
            },
            raw_output=stdout[:10000],
            command_used=" ".join(cmd),
        )
