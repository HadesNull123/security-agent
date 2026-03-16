"""
Findings Parser - Extracts structured Finding objects from tool outputs.
This is the critical bridge between raw tool output and the session findings list.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from src.core.config import Severity
from src.core.models import Finding

logger = logging.getLogger(__name__)


class FindingsParser:
    """
    Parses tool outputs into structured Finding objects.
    Handles output from nuclei, ZAP, Acunetix, sqlmap, commix, and LLM analysis.
    """

    def __init__(self):
        self._seen_hashes: set[str] = set()  # deduplication

    def _dedup_key(self, finding: Finding) -> str:
        """Generate a deduplication key for a finding."""
        return f"{finding.title}|{finding.affected_url or finding.affected_host}|{finding.severity.value}"

    def is_duplicate(self, finding: Finding) -> bool:
        """Check if a finding is a duplicate of one already seen."""
        key = self._dedup_key(finding)
        if key in self._seen_hashes:
            return True
        self._seen_hashes.add(key)
        return False

    # ─── Nuclei ──────────────────────────────────────────────

    def parse_nuclei(self, data: dict[str, Any]) -> list[Finding]:
        """Parse nuclei tool output data into Finding objects."""
        findings = []
        raw_findings = data.get("findings", [])

        for item in raw_findings:
            severity_str = item.get("severity", "info").lower()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.INFO

            classification = item.get("classification", {})
            cve_ids = []
            if cve_id := classification.get("cve-id"):
                if isinstance(cve_id, list):
                    cve_ids = cve_id
                elif isinstance(cve_id, str):
                    cve_ids = [cve_id]

            cvss_score = None
            if cvss := classification.get("cvss-score"):
                try:
                    cvss_score = float(cvss)
                except (ValueError, TypeError):
                    pass

            references = item.get("reference", [])
            if isinstance(references, str):
                references = [references]

            finding = Finding(
                title=item.get("name", item.get("template_id", "Unknown")),
                description=item.get("description", ""),
                severity=severity,
                confidence="high" if severity_str in ("critical", "high") else "medium",
                category=",".join(item.get("tags", [])) if item.get("tags") else "",
                cve_ids=cve_ids,
                cvss_score=cvss_score,
                affected_url=item.get("url", item.get("matched_at", "")),
                affected_host=item.get("host", ""),
                evidence=item.get("curl_command", ""),
                remediation="",
                tool_source="nuclei",
                references=references,
                extra_data={
                    "template_id": item.get("template_id", ""),
                    "matcher_name": item.get("matcher_name", ""),
                    "type": item.get("type", ""),
                    "extracted_results": item.get("extracted_results", []),
                },
            )
            findings.append(finding)

        return findings

    # ─── ZAP ─────────────────────────────────────────────────

    def parse_zap(self, data: dict[str, Any]) -> list[Finding]:
        """Parse ZAP tool output data into Finding objects."""
        findings = []
        alerts = data.get("alerts", [])

        risk_map = {
            "3": Severity.HIGH,  # ZAP High
            "2": Severity.MEDIUM,
            "1": Severity.LOW,
            "0": Severity.INFO,
        }

        for alert in alerts:
            risk = str(alert.get("risk", "0"))
            severity = risk_map.get(risk, Severity.INFO)

            finding = Finding(
                title=alert.get("name", alert.get("alert", "Unknown")),
                description=alert.get("description", ""),
                severity=severity,
                confidence=alert.get("confidence", "medium"),
                category=alert.get("cweid", ""),
                affected_url=alert.get("url", ""),
                evidence=alert.get("evidence", ""),
                remediation=alert.get("solution", ""),
                tool_source="zap",
                references=[alert.get("reference", "")] if alert.get("reference") else [],
            )
            findings.append(finding)

        return findings

    # ─── Acunetix ────────────────────────────────────────────

    def parse_acunetix(self, data: dict[str, Any]) -> list[Finding]:
        """Parse Acunetix tool output data into Finding objects."""
        findings = []
        vulns = data.get("vulnerabilities", [])

        severity_map = {
            4: Severity.CRITICAL,
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
        }

        for vuln in vulns:
            sev_int = vuln.get("severity", 0)
            severity = severity_map.get(sev_int, Severity.INFO)

            # Build description with impact if available
            desc_parts = []
            if vuln.get("description"):
                desc_parts.append(vuln["description"])
            if vuln.get("impact"):
                desc_parts.append(f"\n\n**Impact:** {vuln['impact']}")
            description = "".join(desc_parts) or vuln.get("vt_name", "")

            # Build evidence from request/response
            evidence_parts = []
            if vuln.get("request"):
                evidence_parts.append(f"Request:\n{vuln['request']}")
            if vuln.get("response_info"):
                evidence_parts.append(f"Response:\n{vuln['response_info']}")
            if vuln.get("affects_detail"):
                evidence_parts.append(f"Detail: {vuln['affects_detail']}")
            evidence = "\n\n".join(evidence_parts)

            # CVSS score
            cvss_score = None
            if vuln.get("cvss_score"):
                try:
                    cvss_score = float(vuln["cvss_score"])
                except (ValueError, TypeError):
                    pass

            # References
            references = vuln.get("references", [])
            if isinstance(references, str):
                references = [references]

            # Tags as category
            tags = vuln.get("tags", [])
            category = ",".join(tags) if tags else ""

            # Confidence mapping
            conf = vuln.get("confidence", 0)
            if conf >= 80:
                confidence = "high"
            elif conf >= 50:
                confidence = "medium"
            else:
                confidence = "low"

            finding = Finding(
                title=vuln.get("vt_name", "Unknown"),
                description=description,
                severity=severity,
                confidence=confidence,
                category=category,
                cvss_score=cvss_score,
                affected_url=vuln.get("affects_url", ""),
                evidence=evidence,
                remediation=vuln.get("recommendation", ""),
                tool_source="acunetix",
                references=references,
                extra_data={
                    "vuln_id": vuln.get("vuln_id", ""),
                    "cvss3": vuln.get("cvss3", ""),
                    "criticality": vuln.get("criticality", 0),
                },
            )
            findings.append(finding)

        return findings

    # ─── SQLMap ───────────────────────────────────────────────

    def parse_sqlmap(self, data: dict[str, Any]) -> list[Finding]:
        """Parse SQLMap output into findings."""
        findings = []
        if data.get("injectable") or data.get("databases") or "injectable" in str(data).lower():
            finding = Finding(
                title="SQL Injection Confirmed",
                description=f"SQLMap confirmed SQL injection at {data.get('target', 'unknown')}",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                category="sqli",
                affected_url=data.get("target", ""),
                evidence=json.dumps(data.get("databases", data.get("injection_points", {})), default=str)[:2000],
                remediation="Use parameterized queries/prepared statements. Apply input validation.",
                tool_source="sqlmap",
            )
            findings.append(finding)
        return findings

    # ─── Commix ──────────────────────────────────────────────

    def parse_commix(self, data: dict[str, Any]) -> list[Finding]:
        """Parse Commix output into findings."""
        findings = []
        if data.get("injectable") or "injectable" in str(data).lower():
            finding = Finding(
                title="OS Command Injection Confirmed",
                description=f"Commix confirmed command injection at {data.get('target', 'unknown')}",
                severity=Severity.CRITICAL,
                confidence="confirmed",
                category="command_injection",
                affected_url=data.get("target", ""),
                evidence=str(data.get("output", ""))[:2000],
                remediation="Avoid passing user input to system commands. Use allowlists for inputs.",
                tool_source="commix",
            )
            findings.append(finding)
        return findings

    # ─── ffuf ──────────────────────────────────────────────────

    def parse_ffuf(self, data: dict[str, Any]) -> list[Finding]:
        """Parse ffuf output into findings (interesting dirs/files found)."""
        findings = []
        results = data.get("results", [])

        # Sensitive path patterns that warrant a finding
        sensitive_patterns = {
            ".env", ".git", "wp-config", "phpinfo", "backup", ".htpasswd",
            "admin", "config", ".svn", "debug", "server-status", "elmah",
            "actuator", ".DS_Store", "web.config",
        }

        for item in results:
            url = item.get("url", "")
            status = item.get("status", 0)
            length = item.get("length", 0)
            path = item.get("input", {}).get("FUZZ", url)

            # Only create findings for interesting results
            is_sensitive = any(p in path.lower() for p in sensitive_patterns)
            if status == 200 and is_sensitive:
                finding = Finding(
                    title=f"Sensitive path exposed: {path}",
                    description=f"ffuf discovered accessible sensitive path at {url} (status: {status}, length: {length})",
                    severity=Severity.MEDIUM if length > 0 else Severity.LOW,
                    confidence="medium",
                    category="exposure",
                    affected_url=url,
                    evidence=f"HTTP {status}, Content-Length: {length}",
                    remediation="Restrict access to sensitive files and directories. Use .htaccess or web server rules.",
                    tool_source="ffuf",
                )
                findings.append(finding)

        return findings

    # ─── gobuster ─────────────────────────────────────────────

    def parse_gobuster(self, data: dict[str, Any]) -> list[Finding]:
        """Parse gobuster output into findings."""
        findings = []
        results = data.get("results", data.get("dirs", []))

        sensitive_patterns = {
            ".env", ".git", "wp-config", "phpinfo", "backup", ".htpasswd",
            "admin", "config", ".svn", "debug", "server-status",
        }

        for item in results:
            if isinstance(item, dict):
                path = item.get("path", item.get("url", ""))
                status = item.get("status", 0)
            elif isinstance(item, str):
                path = item
                status = 200
            else:
                continue

            is_sensitive = any(p in path.lower() for p in sensitive_patterns)
            if is_sensitive:
                finding = Finding(
                    title=f"Sensitive directory found: {path}",
                    description=f"gobuster discovered sensitive path: {path} (status: {status})",
                    severity=Severity.MEDIUM,
                    confidence="medium",
                    category="exposure",
                    affected_url=path,
                    evidence=f"HTTP {status}",
                    remediation="Restrict access to sensitive files and directories.",
                    tool_source="gobuster",
                )
                findings.append(finding)

        return findings

    # ─── Secret Scanner ───────────────────────────────────────

    def parse_secret_scanner(self, data: dict[str, Any]) -> list[Finding]:
        """Parse secret_scanner output into findings."""
        findings = []
        raw_findings = data.get("findings", [])

        for item in raw_findings:
            secret = item.get("secret", "")
            key_type = item.get("key_type", "Unknown Key")
            url = item.get("url", "")
            match_preview = item.get("match_preview", "")

            # Default severity is HIGH, but CRITICAL for obvious admin/db credentials
            is_critical = any(kw in key_type.lower() for kw in ("admin", "password", "db", "secret", "aws"))
            severity = Severity.CRITICAL if is_critical else Severity.HIGH

            finding = Finding(
                title=f"Leaked Credential: {key_type}",
                description=f"A leaked credential ({key_type}) was found exposed in the source code at {url}.",
                severity=severity,
                confidence="high",
                category="credential_exposure",
                affected_url=url,
                evidence=f"Match:\n{match_preview}\n\nExtracted Secret: {secret}",
                remediation="Revoke the exposed credentials immediately. Remove the secrets from the source code and use environment variables or a secure vault instead.",
                tool_source="secret_scanner",
            )
            findings.append(finding)

        return findings

    # ─── LLM Analysis Text ───────────────────────────────────

    def parse_llm_analysis(self, text: str) -> list[Finding]:
        """
        Parse structured findings from LLM analysis text.
        Looks for JSON blocks or structured patterns in the analysis output.
        """
        findings = []

        # Try to find JSON blocks in the text
        json_blocks = re.findall(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        for block in json_blocks:
            try:
                data = json.loads(block)
                if isinstance(data, list):
                    for item in data:
                        finding = self._parse_finding_dict(item)
                        if finding:
                            findings.append(finding)
                elif isinstance(data, dict):
                    if "findings" in data:
                        for item in data["findings"]:
                            finding = self._parse_finding_dict(item)
                            if finding:
                                findings.append(finding)
                    else:
                        finding = self._parse_finding_dict(data)
                        if finding:
                            findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def _parse_finding_dict(self, d: dict) -> Finding | None:
        """Parse a dict into a Finding, handling flexible key names."""
        title = d.get("title") or d.get("name") or d.get("vulnerability")
        if not title:
            return None

        severity_str = (d.get("severity") or d.get("risk") or "info").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        return Finding(
            title=title,
            description=d.get("description", ""),
            severity=severity,
            confidence=d.get("confidence", "medium"),
            category=d.get("category", ""),
            affected_url=d.get("affected_url") or d.get("url") or d.get("affected", ""),
            affected_host=d.get("affected_host") or d.get("host", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation") or d.get("fix") or d.get("recommendation", ""),
            tool_source=d.get("tool_source") or d.get("tool", "llm_analysis"),
        )

    # ─── Auto-dispatch ───────────────────────────────────────

    def parse_tool_result(self, tool_name: str, data: dict[str, Any]) -> list[Finding]:
        """
        Auto-detect tool type and parse findings.
        Returns list of non-duplicate findings.
        """
        parsers = {
            "nuclei": self.parse_nuclei,
            "zap": self.parse_zap,
            "acunetix": self.parse_acunetix,
            "sqlmap": self.parse_sqlmap,
            "commix": self.parse_commix,
            "ffuf": self.parse_ffuf,
            "gobuster": self.parse_gobuster,
            "secret_scanner": self.parse_secret_scanner,
        }

        parser = parsers.get(tool_name)
        if not parser:
            return []

        try:
            raw_findings = parser(data)
            # Deduplicate
            unique_findings = []
            for f in raw_findings:
                if not self.is_duplicate(f):
                    unique_findings.append(f)
            return unique_findings
        except Exception as e:
            logger.warning(f"Failed to parse findings from {tool_name}: {e}")
            return []
