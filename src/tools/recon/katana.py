"""Katana - Web crawler/spider tool wrapper."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_lines


class KatanaTool(BaseTool):
    name = "katana"
    description = "Crawl a web application to discover URLs, endpoints, and attack surface"
    phase = ScanPhase.RECON

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        # Ensure target has a URL scheme — katana exits instantly without it
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"https://{target}"

        cmd = ["katana", "-u", target, "-json", "-silent"]

        # Crawl depth — default 3
        depth = kwargs.get("depth", 3)
        cmd.extend(["-d", str(depth)])

        # ★ Max URLs to crawl — prevent endless crawling on large sites
        max_urls = kwargs.get("max_urls", 500)
        cmd.extend(["-em", str(max_urls)])

        # Concurrency — default 20
        concurrency = kwargs.get("concurrency", 20)
        cmd.extend(["-c", str(concurrency)])

        # ★ Rate limit — default 100 req/s
        rate_limit = kwargs.get("rate_limit", 100)
        cmd.extend(["-rl", str(rate_limit)])

        # Headless mode
        if kwargs.get("headless"):
            cmd.append("-headless")

        # Scope: only crawl same root domain (rdn = root domain name)
        cmd.extend(["-fs", kwargs.get("field_scope", "rdn")])

        # JS crawling — discover JS files for secret scanning
        if kwargs.get("js_crawl", True):
            cmd.append("-jc")

        # Known file discovery (JS, CSS, images, etc.)
        cmd.extend(["-kf", "all"])

        # ★ Timeout per request
        cmd.extend(["-timeout", "10"])

        returncode, stdout, stderr = await run_command(cmd)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"katana exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        results = parse_json_lines(stdout)
        urls = []
        for r in results:
            url_info = {
                "url": r.get("request", {}).get("endpoint", r.get("url", "")),
                "method": r.get("request", {}).get("method", "GET"),
                "status_code": r.get("response", {}).get("status_code", 0),
                "content_type": r.get("response", {}).get("headers", {}).get("content_type", ""),
            }
            if url_info["url"]:
                urls.append(url_info)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "target": target,
                "urls": urls,
                "count": len(urls),
            },
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
