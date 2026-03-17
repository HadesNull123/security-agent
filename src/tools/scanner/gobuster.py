"""Gobuster - Directory/DNS/VHost brute-forcing tool wrapper."""

from __future__ import annotations

import logging
import re
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, ensure_wordlist

logger = logging.getLogger(__name__)

# Regex to extract wildcard response length from gobuster error
# Example: "the server returns a status code that matches the provided options for non existing urls. http://example.com/... => 302 (Length: 0)"
_WILDCARD_LENGTH_RE = re.compile(r"Length:\s*(\d+)", re.IGNORECASE)
_WILDCARD_STATUS_RE = re.compile(r"=>\s*(\d{3})", re.IGNORECASE)


class GobusterTool(BaseTool):
    name = "gobuster"
    description = "Brute-force directories, files, DNS subdomains, and virtual hosts"
    phase = ScanPhase.SCANNING

    def _build_cmd(self, target: str, **kwargs: Any) -> list[str]:
        """Build the gobuster command list."""
        mode = kwargs.get("mode", "dir")
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

        return cmd, mode

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd, mode = self._build_cmd(target, **kwargs)

        returncode, stdout, stderr = await run_command(cmd)

        # ★ AUTO-RETRY: detect wildcard and retry with exclusion
        if returncode != 0 and stderr and "the server returns a" in stderr.lower():
            logger.info("🔄 Gobuster detected wildcard response — auto-retrying with exclusion...")

            # Extract wildcard response length from error message
            exclude_length = None
            len_match = _WILDCARD_LENGTH_RE.search(stderr)
            if len_match:
                exclude_length = len_match.group(1)

            # Extract wildcard status code
            wildcard_status = None
            status_match = _WILDCARD_STATUS_RE.search(stderr)
            if status_match:
                wildcard_status = status_match.group(1)

            # Build retry command with exclusions
            retry_cmd = list(cmd)  # copy
            if exclude_length:
                retry_cmd.extend(["--exclude-length", exclude_length])
                logger.info(f"  → Excluding response length: {exclude_length}")
            if wildcard_status:
                # Add --no-error to ignore wildcard detection
                retry_cmd.append("--no-error")
                logger.info(f"  → Wildcard status {wildcard_status}, adding --no-error")

            # If we couldn't extract specifics, just add --no-error as fallback
            if not exclude_length and not wildcard_status:
                retry_cmd.append("--no-error")
                logger.info("  → Could not parse wildcard details, adding --no-error")

            logger.info(f"🔄 Retry command: {' '.join(retry_cmd[:15])}...")
            returncode, stdout, stderr = await run_command(retry_cmd)
            cmd = retry_cmd  # update for command_used reporting

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"gobuster exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse gobuster text output
        results_list = self._parse_output(stdout)

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

    @staticmethod
    def _parse_output(stdout: str) -> list[dict]:
        """Parse gobuster text output into structured results."""
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
        return results_list
