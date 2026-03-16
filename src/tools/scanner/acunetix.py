"""Acunetix - Commercial web vulnerability scanner API wrapper.

Full API integration supporting:
- Target creation and configuration
- Scan scheduling with multiple profiles
- Scan status polling
- Vulnerability listing and detail fetching (description, impact, recommendation, CVSS)
- Findings output compatible with findings_parser.py
"""

from __future__ import annotations
import asyncio
import logging
from typing import Any
import httpx
from src.core.config import ScanPhase, AcunetixConfig
from src.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class AcunetixTool(BaseTool):
    name = "acunetix"
    description = "Acunetix web vulnerability scanner via REST API - supports full, High Risk, XSS, SQLi scan profiles"
    phase = ScanPhase.SCANNING

    # Well-known scan profile IDs
    PROFILES = {
        "full": "11111111-1111-1111-1111-111111111111",
        "high_risk": "11111111-1111-1111-1111-111111111112",
        "sqli": "11111111-1111-1111-1111-111111111113",
        "weak_passwords": "11111111-1111-1111-1111-111111111115",
        "xss": "11111111-1111-1111-1111-111111111116",
        "crawl_only": "11111111-1111-1111-1111-111111111117",
        "malware": "11111111-1111-1111-1111-111111111120",
    }

    def __init__(self, config: AcunetixConfig, **kwargs):
        super().__init__()
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
                # ── Step 1: Add target ──
                target_id = await self._add_target(client, target)
                logger.info(f"Acunetix target created: {target_id}")

                # ── Step 2: Schedule scan ──
                scan_id = await self._schedule_scan(client, target_id, profile_id)
                logger.info(f"Acunetix scan started: {scan_id} (profile={profile_name})")

                if not wait_for_completion:
                    return ToolResult(
                        tool_name=self.name,
                        success=True,
                        data={
                            "target": target,
                            "target_id": target_id,
                            "scan_id": scan_id,
                            "status": "scan_started",
                            "profile": profile_name,
                        },
                        command_used=f"acunetix scan {target} --profile {profile_name}",
                    )

                # ── Step 3: Poll scan status ──
                final_status, result_id = await self._poll_scan(client, scan_id)
                logger.info(f"Acunetix scan finished: status={final_status}, result_id={result_id}")

                if final_status not in ("completed", "failed"):
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        error=f"Scan did not complete in time. Final status: {final_status}",
                        data={"target": target, "scan_id": scan_id, "status": final_status},
                        command_used=f"acunetix scan {target} --profile {profile_name}",
                    )

                # ── Step 4: Get vulnerabilities ──
                vulns_summary = await self._get_vulnerabilities(client, scan_id, result_id)

                # ── Step 5: Fetch detail for top vulnerabilities ──
                detailed_findings = await self._fetch_vuln_details(client, vulns_summary[:50])

                # Build severity summary
                severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
                severity_counts: dict[str, int] = {}
                for f in detailed_findings:
                    sev = severity_map.get(f.get("severity", 0), "info")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    data={
                        "target": target,
                        "target_id": target_id,
                        "scan_id": scan_id,
                        "profile": profile_name,
                        "status": final_status,
                        "vulnerabilities": detailed_findings,
                        "count": len(detailed_findings),
                        "severity_summary": severity_counts,
                    },
                    command_used=f"acunetix scan {target} --profile {profile_name}",
                )

        except httpx.HTTPStatusError as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Acunetix API HTTP error: {e.response.status_code} - {e.response.text[:500]}",
                command_used=f"acunetix scan {target}",
            )
        except httpx.ConnectError as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Cannot connect to Acunetix at {self.base_url}: {str(e)}",
                command_used=f"acunetix scan {target}",
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Acunetix error: {str(e)}",
                command_used=f"acunetix scan {target}",
            )

    # ─── Private API methods ─────────────────────────────────

    async def _add_target(self, client: httpx.AsyncClient, target: str) -> str:
        """POST /api/v1/targets — Create a new scan target."""
        resp = await client.post(
            f"{self.base_url}/api/v1/targets",
            json={
                "address": target,
                "description": f"Security Agent scan - {target}",
                "criticality": 10,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("target_id", "")

    async def _schedule_scan(self, client: httpx.AsyncClient, target_id: str, profile_id: str) -> str:
        """POST /api/v1/scans — Schedule a scan for the target."""
        resp = await client.post(
            f"{self.base_url}/api/v1/scans",
            json={
                "target_id": target_id,
                "profile_id": profile_id,
                "schedule": {
                    "disable": False,
                    "start_date": None,
                    "time_sensitive": False,
                },
            },
        )
        resp.raise_for_status()

        # Scan ID is in the Location header or response body
        location = resp.headers.get("Location", "")
        if location:
            # Location: /api/v1/scans/{scan_id}
            scan_id = location.rstrip("/").split("/")[-1]
        else:
            scan_id = resp.json().get("scan_id", "")

        return scan_id

    async def _poll_scan(self, client: httpx.AsyncClient, scan_id: str) -> tuple[str, str]:
        """
        GET /api/v1/scans/{scan_id} — Poll until scan completes.
        Returns (final_status, result_id).
        """
        result_id = ""
        final_status = "unknown"

        for i in range(360):  # max ~30 min (360 * 5s)
            try:
                resp = await client.get(f"{self.base_url}/api/v1/scans/{scan_id}")
                resp.raise_for_status()
                scan_data = resp.json()

                session = scan_data.get("current_session", {})
                status = session.get("status", "unknown")
                progress = session.get("progress", 0)

                if i % 12 == 0:  # Log every 60s
                    logger.info(f"Acunetix scan {scan_id}: status={status}, progress={progress}%")

                if status in ("completed", "failed", "aborted"):
                    final_status = status
                    result_id = session.get("scan_session_id", "")
                    break

                await asyncio.sleep(5)

            except Exception as e:
                logger.warning(f"Error polling Acunetix scan: {e}")
                await asyncio.sleep(10)

        return final_status, result_id

    async def _get_vulnerabilities(
        self, client: httpx.AsyncClient, scan_id: str, result_id: str
    ) -> list[dict[str, Any]]:
        """
        GET /api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities
        Returns a list of vulnerability summaries.
        Falls back to GET /api/v1/vulnerabilities if result_id is missing.
        """
        vulns: list[dict[str, Any]] = []

        try:
            if result_id:
                # Use the specific scan result endpoint
                url = f"{self.base_url}/api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities"
            else:
                # Fallback: get all vulns and filter by scan
                url = f"{self.base_url}/api/v1/vulnerabilities"

            # Paginate through all results
            cursor = 0
            while True:
                params = {"l": "100", "c": str(cursor)}
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()

                page_vulns = data.get("vulnerabilities", [])
                if not page_vulns:
                    break

                for v in page_vulns:
                    vulns.append({
                        "vuln_id": v.get("vuln_id", ""),
                        "severity": v.get("severity", 0),
                        "vt_name": v.get("vt_name", ""),
                        "affects_url": v.get("affects_url", ""),
                        "affects_detail": v.get("affects_detail", ""),
                        "confidence": v.get("confidence", 0),
                        "status": v.get("status", ""),
                        "criticality": v.get("criticality", 0),
                        "target_id": v.get("target_id", ""),
                    })

                # Check if there are more pages
                pagination = data.get("pagination", {})
                next_cursor = pagination.get("next_cursor")
                if not next_cursor or len(page_vulns) < 100:
                    break
                cursor = next_cursor

        except Exception as e:
            logger.warning(f"Error fetching Acunetix vulnerabilities: {e}")

        return vulns

    async def _fetch_vuln_details(
        self, client: httpx.AsyncClient, vulns: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        GET /api/v1/vulnerabilities/{vuln_id} — Fetch detailed info for each vulnerability.
        Enriches each vuln dict with description, impact, recommendation, CVSS, references.
        """
        detailed = []

        for v in vulns:
            vuln_id = v.get("vuln_id", "")
            if not vuln_id:
                detailed.append(v)
                continue

            try:
                resp = await client.get(f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}")
                if resp.status_code == 200:
                    detail = resp.json()
                    v["description"] = detail.get("description", "")
                    v["impact"] = detail.get("impact", "")
                    v["recommendation"] = detail.get("recommendation", "")
                    v["request"] = detail.get("request", "")[:500]
                    v["response_info"] = detail.get("response_info", "")[:500]
                    v["cvss_score"] = detail.get("cvss_score")
                    v["cvss3"] = detail.get("cvss3", "")
                    v["tags"] = detail.get("tags", [])

                    # Extract references (CWE, CVE, external links)
                    refs = detail.get("references", [])
                    v["references"] = []
                    for ref in refs:
                        if isinstance(ref, dict):
                            v["references"].append(ref.get("href", ""))
                        elif isinstance(ref, str):
                            v["references"].append(ref)

            except Exception as e:
                logger.debug(f"Failed to fetch detail for vuln {vuln_id}: {e}")

            detailed.append(v)

            # Small delay to avoid overwhelming the API
            await asyncio.sleep(0.2)

        return detailed
