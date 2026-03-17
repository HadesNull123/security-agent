"""Email Security Scanner — checks DKIM, DMARC, SPF, MX, DNSBL, and mail server exposure."""

from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult


class EmailSecurityTool(BaseTool):
    name = "email_security"
    description = (
        "Check email security configuration for a domain: "
        "SPF (Sender Policy Framework), DKIM, DMARC, MX records, "
        "mail server exposure, and DNSBL (blacklist) status."
    )
    phase = ScanPhase.SCANNING

    def is_available(self) -> bool:
        return shutil.which("dig") is not None or shutil.which("nslookup") is not None

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        # Strip protocol to get domain
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        results: dict[str, Any] = {
            "domain": domain,
            "spf": await self._check_spf(domain),
            "dmarc": await self._check_dmarc(domain),
            "dkim": await self._check_dkim(domain, kwargs.get("dkim_selector", "default")),
            "mx": await self._check_mx(domain),
            "dnsbl": await self._check_dnsbl(domain),
        }

        findings = self._analyze(results)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={
                "domain": domain,
                "records": results,
                "findings": findings,
                "count": len(findings),
            },
            raw_output=str(results),
            command_used=f"email_security check {domain}",
        )

    async def _dig(self, qtype: str, name: str) -> str:
        """Run dig query and return output."""
        if shutil.which("dig"):
            cmd = ["dig", "+short", qtype, name]
        else:
            cmd = ["nslookup", "-type=" + qtype, name]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    async def _check_spf(self, domain: str) -> dict:
        output = await self._dig("TXT", domain)
        spf_record = ""
        for line in output.splitlines():
            if "v=spf1" in line.lower():
                spf_record = line.strip('"').strip()
                break

        issues = []
        if not spf_record:
            issues.append("No SPF record found — domain is vulnerable to email spoofing")
        else:
            if "+all" in spf_record:
                issues.append("SPF uses '+all' — allows ANY server to send email (CRITICAL)")
            elif "?all" in spf_record:
                issues.append("SPF uses '?all' — neutral policy, provides no protection (MEDIUM)")
            elif "~all" in spf_record:
                issues.append("SPF uses '~all' (softfail) — emails from unknown sources may still be delivered (LOW)")
            # Check include count (max 10 DNS lookups)
            includes = re.findall(r"include:", spf_record)
            if len(includes) > 8:
                issues.append(f"SPF has {len(includes)} includes — approaching 10-lookup limit (RFC 7208)")

        return {
            "record": spf_record,
            "valid": bool(spf_record),
            "issues": issues,
        }

    async def _check_dmarc(self, domain: str) -> dict:
        output = await self._dig("TXT", f"_dmarc.{domain}")
        dmarc_record = ""
        for line in output.splitlines():
            if "v=dmarc1" in line.lower():
                dmarc_record = line.strip('"').strip()
                break

        issues = []
        policy = ""
        if not dmarc_record:
            issues.append("No DMARC record found — phishing via this domain goes unreported")
        else:
            # Extract policy
            m = re.search(r"p=(\w+)", dmarc_record, re.IGNORECASE)
            if m:
                policy = m.group(1).lower()
                if policy == "none":
                    issues.append("DMARC policy is 'none' — only monitoring, no enforcement (MEDIUM)")
                elif policy == "quarantine":
                    issues.append("DMARC policy is 'quarantine' — spoofed emails go to spam (good, but not reject)")
                # "reject" is the best policy

            # Check rua (aggregate reports)
            if "rua=" not in dmarc_record.lower():
                issues.append("No DMARC aggregate report (rua=) configured — blind to abuse")

        return {
            "record": dmarc_record,
            "valid": bool(dmarc_record),
            "policy": policy,
            "issues": issues,
        }

    async def _check_dkim(self, domain: str, selector: str = "default") -> dict:
        """Check DKIM for common selectors."""
        common_selectors = [selector, "default", "google", "mail", "email",
                            "dkim", "s1", "s2", "k1", "selector1", "selector2"]
        found = []
        for sel in common_selectors:
            output = await self._dig("TXT", f"{sel}._domainkey.{domain}")
            if "v=dkim1" in output.lower() or "p=" in output.lower():
                found.append({"selector": sel, "record": output.strip('"').strip()})

        issues = []
        if not found:
            issues.append(f"No DKIM records found for common selectors — email authenticity unverifiable")
        else:
            for entry in found:
                record = entry["record"]
                # Check key size (p= field length — RSA 1024 ≈ 216 chars, 2048 ≈ 392 chars)
                m = re.search(r"p=([A-Za-z0-9+/=]+)", record)
                if m:
                    key_data = m.group(1)
                    if len(key_data) < 200:
                        issues.append(f"DKIM selector '{entry['selector']}' may use RSA-1024 (weak key) — upgrade to RSA-2048")

        return {
            "selectors_found": found,
            "valid": bool(found),
            "issues": issues,
        }

    async def _check_mx(self, domain: str) -> dict:
        output = await self._dig("MX", domain)
        mx_records = [line.strip() for line in output.splitlines() if line.strip()]

        issues = []
        if not mx_records:
            issues.append("No MX records found — domain does not accept email")
        else:
            # Check for open relay indicators in hostnames
            for mx in mx_records:
                if any(kw in mx.lower() for kw in ["mail.", "smtp.", "exchange.", "relay."]):
                    pass  # Normal
            if len(mx_records) == 1:
                issues.append("Only 1 MX record — no mail server redundancy (LOW)")

        return {
            "records": mx_records,
            "count": len(mx_records),
            "issues": issues,
        }

    async def _check_dnsbl(self, domain: str) -> dict:
        """Check if domain's A record IP is on common blacklists."""
        # Get A record
        ip_output = await self._dig("A", domain)
        ips = [line.strip() for line in ip_output.splitlines() if re.match(r"\d+\.\d+\.\d+\.\d+", line.strip())]

        if not ips:
            return {"checked": False, "issues": ["Could not resolve domain IP for DNSBL check"]}

        ip = ips[0]
        # Reverse IP for DNSBL check
        rev_ip = ".".join(reversed(ip.split(".")))

        dnsbls = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
        ]

        listed = []
        for bl in dnsbls:
            output = await self._dig("A", f"{rev_ip}.{bl}")
            if output and "127." in output:
                listed.append(bl)

        issues = []
        if listed:
            issues.append(f"IP {ip} is blacklisted on: {', '.join(listed)} — mail delivery likely blocked")

        return {
            "ip": ip,
            "blacklists_checked": dnsbls,
            "listed_on": listed,
            "issues": issues,
        }

    def _analyze(self, results: dict) -> list[dict]:
        """Convert all issues to structured findings."""
        findings = []

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for section, data in results.items():
            if section == "domain":
                continue
            for issue in data.get("issues", []):
                sev = "medium"
                for kw, s in severity_map.items():
                    if kw in issue.upper():
                        sev = s
                        break
                if "No SPF" in issue or "No DMARC" in issue:
                    sev = "high"
                if "blacklisted" in issue.lower():
                    sev = "high"

                findings.append({
                    "check": section.upper(),
                    "issue": issue,
                    "severity": sev,
                    "remediation": self._remediation_hint(section, issue),
                })
        return findings

    def _remediation_hint(self, section: str, issue: str) -> str:
        hints = {
            "spf": (
                "Add TXT record: 'v=spf1 include:_spf.google.com ~all'\n"
                "Use '-all' (hard fail) for strict enforcement."
            ),
            "dmarc": (
                "Add TXT record at _dmarc.domain.com:\n"
                "'v=DMARC1; p=reject; rua=mailto:dmarc@domain.com; ruf=mailto:dmarc@domain.com; fo=1'"
            ),
            "dkim": (
                "Generate RSA-2048 DKIM key pair and publish public key as TXT record:\n"
                "selector._domainkey.domain.com IN TXT 'v=DKIM1; k=rsa; p=<public-key>'"
            ),
            "dnsbl": (
                "Visit https://www.spamhaus.org/lookup/ to request delisting.\n"
                "Investigate outgoing mail for spam/compromised accounts."
            ),
            "mx": "Add backup MX record for redundancy.",
        }
        return hints.get(section, "")
