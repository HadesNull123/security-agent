"""Nuclei - Template-based vulnerability scanner tool wrapper."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines

logger = logging.getLogger(__name__)


class NucleiTool(BaseTool):
    name = "nuclei"
    description = (
        "Scan targets for vulnerabilities using YAML-based templates. "
        "Supports scanning for CVEs, misconfigurations, default credentials, exposed panels, and more. "
        "Set fuzz=true for deep fuzzing with nuclei's fuzzing templates."
    )
    phase = ScanPhase.SCANNING
    _templates_checked = False  # Class-level: only update once per process

    async def _ensure_templates(self) -> None:
        """Ensure nuclei templates are downloaded. Critical — without templates nuclei exits in 2s."""
        if NucleiTool._templates_checked:
            return

        # Check if templates directory exists and has content
        home = Path.home()
        template_dirs = [
            home / "nuclei-templates",
            home / ".local" / "nuclei-templates",
            home / ".config" / "nuclei" / "templates",
        ]
        has_templates = any(
            d.exists() and any(d.rglob("*.yaml"))
            for d in template_dirs
        )

        if not has_templates:
            logger.info("📥 Nuclei templates not found — downloading (first run)...")
            rc, out, err = await run_command(["nuclei", "-update-templates"])
            if rc == 0:
                logger.info("✅ Nuclei templates downloaded successfully")
            else:
                logger.warning(f"⚠️ Nuclei template update returned code {rc}: {err[:300]}")
        else:
            # Still check for updates periodically (non-blocking)
            logger.info("📋 Nuclei templates found, checking for updates...")
            rc, out, err = await run_command(["nuclei", "-update-templates", "-ut"])
            if rc == 0:
                logger.info("✅ Nuclei templates up to date")

        NucleiTool._templates_checked = True

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        # ★ CRITICAL: ensure templates are downloaded before scanning
        await self._ensure_templates()

        cmd = ["nuclei", "-u", target, "-jsonl", "-no-color"]

        # Template selection
        has_filter = False
        if templates := kwargs.get("templates"):
            cmd.extend(["-t", templates])
            has_filter = True
        if severity := kwargs.get("severity"):
            cmd.extend(["-severity", severity])
            has_filter = True
        if exclude_tags := kwargs.get("exclude_tags"):
            cmd.extend(["-etags", exclude_tags])

        # Template IDs
        if template_ids := kwargs.get("template_ids"):
            cmd.extend(["-id", template_ids])
            has_filter = True

        # ★ Fuzzing mode: ONLY fuzzing templates, no mixing
        is_fuzz = kwargs.get("fuzz", False)

        if is_fuzz:
            # Pure fuzzing: nuclei -u target -t fuzzing/ -fuzz -fa high
            fuzz_sev = kwargs.get("fuzz_severity", "high")
            cmd.extend(["-t", "fuzzing/", "-fuzz", "-fa", fuzz_sev])
        elif not has_filter:
            # ★ Normal scan: just severity filter, no tags
            cmd.extend(["-severity", "critical,high,medium,low"])

        # Rate control
        if rate_limit := kwargs.get("rate_limit"):
            cmd.extend(["-rl", str(rate_limit)])
        else:
            cmd.extend(["-rl", "150"])  # Default: 150 req/s
        if concurrency := kwargs.get("concurrency"):
            cmd.extend(["-c", str(concurrency)])
        else:
            cmd.extend(["-c", "25"])  # Default: 25 concurrent templates

        # Custom headers
        if headers := kwargs.get("headers"):
            for h in headers:
                cmd.extend(["-H", h])

        # Proxy
        if proxy := kwargs.get("proxy"):
            cmd.extend(["-proxy", proxy])

        # Performance tuning
        cmd.extend([
            "-timeout", "15",       # 15s per request
            "-retries", "2",        # Retry failed requests
            "-mhe", "30",           # Max 30 host errors before giving up
            "-stats",               # Show progress stats in stderr
            "-stats-interval", "10",  # Stats every 10s
        ])

        logger.info(f"🔬 Running nuclei: {' '.join(cmd[:20])}...")
        returncode, stdout, stderr = await run_command(cmd)

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
