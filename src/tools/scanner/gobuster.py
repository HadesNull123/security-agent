"""Gobuster - Directory/DNS/VHost brute-forcing tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, ensure_wordlist


class GobusterTool(BaseTool):
    name = "gobuster"
    description = "Brute-force directories, files, DNS subdomains, and virtual hosts"
    phase = ScanPhase.SCANNING

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        mode = kwargs.get("mode", "dir")  # dir, dns, vhost
        cmd = ["gobuster", mode]

        if mode == "dir":
            cmd.extend(["-u", target])
        elif mode == "dns":
            cmd.extend(["-d", target])
        elif mode == "vhost":
            cmd.extend(["-u", target])

        # Wordlist — auto-download if needed
        wordlist = ensure_wordlist(kwargs.get("wordlist"))
        cmd.extend(["-w", wordlist])

        # Common options
        cmd.extend(["-q", "--no-color"])

        # ★ Performance defaults
        threads = kwargs.get("threads", 40)
        cmd.extend(["-t", str(threads)])
        cmd.extend(["--timeout", "10s"])

        if extensions := kwargs.get("extensions"):
            cmd.extend(["-x", extensions])
        if status_codes := kwargs.get("status_codes"):
            cmd.extend(["-s", status_codes])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"gobuster exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse gobuster text output
        results_list = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("="):
                continue
            # Format: /path (Status: 200) [Size: 1234]
            parts = line.split()
            if parts:
                entry = {"path": parts[0]}
                if "(Status:" in line:
                    try:
                        status = line.split("(Status:")[1].split(")")[0].strip()
                        entry["status"] = int(status)
                    except (IndexError, ValueError):
                        pass
                if "[Size:" in line:
                    try:
                        size = line.split("[Size:")[1].split("]")[0].strip()
                        entry["size"] = int(size)
                    except (IndexError, ValueError):
                        pass
                results_list.append(entry)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "mode": mode,
                "results": results_list,
                "count": len(results_list),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
