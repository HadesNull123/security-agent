"""OWASP ZAP - Web application security scanner API wrapper."""

from __future__ import annotations
import asyncio
from typing import Any
import httpx
from src.core.config import ScanPhase, ZAPConfig
from src.tools import BaseTool, ToolResult


class ZAPTool(BaseTool):
    name = "zap"
    description = "OWASP ZAP automated web application security scanner via API"
    phase = ScanPhase.SCANNING

    def __init__(self, config: ZAPConfig, **kwargs):
        super().__init__()
        self.config = config
        self.base_url = config.api_url.rstrip("/")
        self.api_key = config.api_key

    def is_available(self) -> bool:
        return bool(self.config.api_url and self.config.api_key)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _params(self, **extra: Any) -> dict:
        params = {"apikey": self.api_key}
        params.update(extra)
        return params

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        scan_type = kwargs.get("scan_type", "spider_and_active")

        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                results: dict[str, Any] = {"target": target}

                # Step 1: Spider scan
                if scan_type in ("spider", "spider_and_active"):
                    spider_resp = await client.get(
                        self._url("/JSON/spider/action/scan/"),
                        params=self._params(url=target, maxChildren="10"),
                    )
                    spider_data = spider_resp.json()
                    scan_id = spider_data.get("scan", "0")

                    # Wait for spider to complete
                    for _ in range(120):
                        status_resp = await client.get(
                            self._url("/JSON/spider/view/status/"),
                            params=self._params(scanId=scan_id),
                        )
                        status = status_resp.json().get("status", "0")
                        if int(status) >= 100:
                            break
                        await asyncio.sleep(2)

                    # Get spider results
                    urls_resp = await client.get(
                        self._url("/JSON/spider/view/results/"),
                        params=self._params(scanId=scan_id),
                    )
                    results["spider_urls"] = urls_resp.json().get("results", [])[:50]

                # Step 2: Active Scan
                if scan_type in ("active", "spider_and_active"):
                    active_resp = await client.get(
                        self._url("/JSON/ascan/action/scan/"),
                        params=self._params(url=target, recurse="true"),
                    )
                    active_data = active_resp.json()
                    scan_id = active_data.get("scan", "0")

                    # Wait for active scan
                    for _ in range(300):
                        status_resp = await client.get(
                            self._url("/JSON/ascan/view/status/"),
                            params=self._params(scanId=scan_id),
                        )
                        status = status_resp.json().get("status", "0")
                        if int(status) >= 100:
                            break
                        await asyncio.sleep(5)

                # Step 3: Get alerts
                alerts_resp = await client.get(
                    self._url("/JSON/alert/view/alerts/"),
                    params=self._params(baseurl=target, count="100"),
                )
                alerts = alerts_resp.json().get("alerts", [])

                findings = []
                for alert in alerts:
                    findings.append({
                        "name": alert.get("name", ""),
                        "risk": alert.get("risk", ""),
                        "confidence": alert.get("confidence", ""),
                        "description": alert.get("description", "")[:500],
                        "url": alert.get("url", ""),
                        "param": alert.get("param", ""),
                        "evidence": alert.get("evidence", "")[:200],
                        "solution": alert.get("solution", "")[:500],
                        "reference": alert.get("reference", ""),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", ""),
                        "plugin_id": alert.get("pluginId", ""),
                    })

                results["findings"] = findings
                results["count"] = len(findings)

                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data=results,
                    raw_output=str(findings),
                )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"ZAP API error: {str(e)}",
            )
