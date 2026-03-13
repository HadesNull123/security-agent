"""Acunetix - Commercial web vulnerability scanner API wrapper."""

from __future__ import annotations
import asyncio
from typing import Any
import httpx
from src.core.config import ScanPhase, AcunetixConfig
from src.tools import BaseTool, ToolResult


class AcunetixTool(BaseTool):
    name = "acunetix"
    description = "Acunetix web vulnerability scanner via REST API - supports full, High Risk, XSS, SQLi scan profiles"
    phase = ScanPhase.SCANNING

    # Well-known scan profile IDs
    PROFILES = {
        "full": "11111111-1111-1111-1111-111111111111",
        "high_risk": "11111111-1111-1111-1111-111111111112",
        "xss": "11111111-1111-1111-1111-111111111116",
        "sqli": "11111111-1111-1111-1111-111111111113",
        "weak_passwords": "11111111-1111-1111-1111-111111111115",
        "crawl_only": "11111111-1111-1111-1111-111111111117",
    }

    def __init__(self, config: AcunetixConfig, timeout: int = 900):
        super().__init__(timeout=timeout)
        self.config = config
        self.base_url = config.api_url.rstrip("/")
        self.api_key = config.api_key
        self.verify_ssl = config.verify_ssl

    def is_available(self) -> bool:
        return bool(self.config.api_url and self.config.api_key)

    def _headers(self) -> dict:
        return {
            "X-Auth": self.api_key,
            "Content-Type": "application/json",
        }

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        profile_name = kwargs.get("profile", "full")
        profile_id = self.PROFILES.get(profile_name, self.PROFILES["full"])
        wait_for_completion = kwargs.get("wait", True)

        try:
            async with httpx.AsyncClient(
                timeout=60, verify=self.verify_ssl, headers=self._headers()
            ) as client:
                # Step 1: Add target
                add_resp = await client.post(
                    f"{self.base_url}/api/v1/targets",
                    json={
                        "address": target,
                        "description": f"Security Agent scan - {target}",
                        "criticality": 10,
                    },
                )
                add_resp.raise_for_status()
                target_data = add_resp.json()
                target_id = target_data.get("target_id", "")

                # Step 2: Start scan
                scan_resp = await client.post(
                    f"{self.base_url}/api/v1/scans",
                    json={
                        "target_id": target_id,
                        "profile_id": profile_id,
                        "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
                    },
                )
                scan_resp.raise_for_status()

                if not wait_for_completion:
                    return ToolResult(
                        tool_name=self.name,
                        success=True,
                        data={
                            "target": target,
                            "target_id": target_id,
                            "status": "scan_started",
                            "profile": profile_name,
                        },
                    )

                # Step 3: Wait for scan completion
                for _ in range(360):  # max 30 min
                    scans_resp = await client.get(
                        f"{self.base_url}/api/v1/scans",
                        params={"l": "20", "q": f"target_id:{target_id}"},
                    )
                    scans = scans_resp.json().get("scans", [])
                    if scans and scans[0].get("current_session", {}).get("status") == "completed":
                        break
                    await asyncio.sleep(5)

                # Step 4: Get vulnerabilities
                vulns_resp = await client.get(
                    f"{self.base_url}/api/v1/vulnerabilities",
                    params={"l": "100", "q": f"target_id:{target_id}"},
                )
                vulns = vulns_resp.json().get("vulnerabilities", [])

                findings = []
                for v in vulns:
                    findings.append({
                        "vuln_id": v.get("vuln_id", ""),
                        "severity": v.get("severity", 0),  # 0-4
                        "target_id": v.get("target_id", ""),
                        "name": v.get("vt_name", ""),
                        "affects_url": v.get("affects_url", ""),
                        "affects_detail": v.get("affects_detail", ""),
                        "confidence": v.get("confidence", 0),
                        "status": v.get("status", ""),
                        "criticality": v.get("criticality", 0),
                    })

                severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
                severity_counts: dict[str, int] = {}
                for f in findings:
                    sev = severity_map.get(f["severity"], "info")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data={
                        "target": target,
                        "target_id": target_id,
                        "profile": profile_name,
                        "findings": findings,
                        "count": len(findings),
                        "severity_summary": severity_counts,
                    },
                )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Acunetix API error: {str(e)}",
            )
