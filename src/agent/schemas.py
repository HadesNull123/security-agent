"""
Pydantic input schemas for LangChain tool validation.
Gemini-compatible: strips 'title'/'default' keys from JSON schema.
"""

from pydantic import BaseModel, Field


def _strip_schema_keys(schema: dict) -> dict:
    """Recursively strip 'title' and 'default' from JSON schema for Gemini compatibility."""
    cleaned = {}
    for key, value in schema.items():
        if key in ("title", "default"):
            continue
        if isinstance(value, dict):
            cleaned[key] = _strip_schema_keys(value)
        elif isinstance(value, list):
            cleaned[key] = [
                _strip_schema_keys(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            cleaned[key] = value
    return cleaned


class GeminiSafeModel(BaseModel):
    """Base model that produces Gemini-compatible JSON schema (no 'title'/'default' keys)."""

    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        schema = super().model_json_schema(*args, **kwargs)
        return _strip_schema_keys(schema)


# ─── Recon Tools ────────────────────────────────────────────

class SubfinderInput(GeminiSafeModel):
    target: str = Field(description="Domain to enumerate subdomains for")
    sources: str = Field(default="", description="Comma-separated list of sources")

class NaabuInput(GeminiSafeModel):
    target: str = Field(description="Host or IP to scan ports on")
    ports: str = Field(default="", description="Ports to scan, e.g. '80,443' or '1-10000'")
    top_ports: str = Field(default="100", description="Number of top ports to scan")

class KatanaInput(GeminiSafeModel):
    target: str = Field(description="URL to crawl")
    depth: int = Field(default=3, description="Crawl depth")
    js_crawl: bool = Field(default=True, description="Enable JavaScript source crawling")
    headless: bool = Field(default=False, description="Use headless browser")

class HttpxInput(GeminiSafeModel):
    target: str = Field(description="Domain/URL/file for HTTP probing")
    tech_detect: bool = Field(default=True, description="Enable technology detection")
    status_code: bool = Field(default=True, description="Show status codes")
    follow_redirects: bool = Field(default=True, description="Follow redirects")

class AmassInput(GeminiSafeModel):
    target: str = Field(description="Domain for subdomain enumeration")
    mode: str = Field(default="passive", description="Mode: passive or active")

class WhatWebInput(GeminiSafeModel):
    target: str = Field(description="URL or domain for tech fingerprinting")
    aggression: int = Field(default=1, description="Aggression level: 1=stealthy, 3=aggressive")

class Wafw00fInput(GeminiSafeModel):
    target: str = Field(description="URL to detect WAF")

class DnsxInput(GeminiSafeModel):
    target: str = Field(description="Domain or list of domains for DNS resolution")
    record_type: str = Field(default="A", description="DNS record type: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR")
    wordlist: str = Field(default="", description="Wordlist for subdomain brute-force")


# ─── Scanner Tools ──────────────────────────────────────────

class NucleiInput(GeminiSafeModel):
    target: str = Field(description="URL to scan for vulnerabilities")
    severity: str = Field(default="", description="Severity filter: critical,high,medium,low,info")
    rate_limit: int = Field(default=0, description="Requests per second (0=default)")
    fuzz: bool = Field(default=False, description="Enable fuzzing mode with nuclei fuzzing templates (-t fuzzing/ -fuzz)")
    fuzz_severity: str = Field(default="high", description="Minimum severity for fuzz alerts: critical, high, medium, low")

class FfufInput(GeminiSafeModel):
    target: str = Field(description="URL with FUZZ keyword, e.g. http://example.com/FUZZ")
    wordlist: str = Field(default="/usr/share/wordlists/common.txt", description="Wordlist path")
    extensions: str = Field(default="", description="File extensions, e.g. '.php,.html'")
    filter_codes: str = Field(default="404", description="HTTP codes to filter out")
    filter_size: str = Field(default="", description="Response sizes to filter")

class GobusterInput(GeminiSafeModel):
    target: str = Field(description="URL or domain to brute-force")
    mode: str = Field(default="dir", description="Mode: dir, dns, vhost")
    wordlist: str = Field(default="/usr/share/wordlists/common.txt", description="Wordlist path")
    extensions: str = Field(default="", description="File extensions for dir mode")

class NiktoInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with Nikto")
    tuning: str = Field(default="", description="Scan tuning: 1=file upload, 2=misconfig, 3=info, 4=injection, etc.")

class TestSSLInput(GeminiSafeModel):
    target: str = Field(description="Host:port to test SSL/TLS (e.g. example.com:443)")
    checks: str = Field(default="", description="Specific checks: --protocols, --ciphers, --vulnerabilities")

class ZAPInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with ZAP")
    scan_type: str = Field(default="spider_and_active", description="Type: spider, active, spider_and_active")

class SecretScannerInput(GeminiSafeModel):
    target: str = Field(default="", description="Domain or URL to auto-crawl and scan for leaked credentials in JS/CSS/HTML files.")
    urls: str = Field(default="", description="Comma-separated list of specific URLs to scan. If empty, will auto-crawl the target.")

class AcunetixInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with Acunetix")
    profile: str = Field(default="full", description="Scan profile: full, high_risk, xss, sqli")


# ─── Exploit Tools ──────────────────────────────────────────

class SQLMapInput(GeminiSafeModel):
    target: str = Field(description="URL with parameters, e.g. http://example.com/page?id=1")
    level: int = Field(default=1, description="Detection level 1-5")
    risk: int = Field(default=1, description="Risk level 1-3")
    dbs: bool = Field(default=True, description="Enumerate databases")
    param: str = Field(default="", description="Specific parameter to test")

class CommixInput(GeminiSafeModel):
    target: str = Field(description="URL to test for command injection")
    param: str = Field(default="", description="Specific parameter to test")

class SearchSploitInput(GeminiSafeModel):
    query: str = Field(description="Search query, e.g. 'Apache 2.4.49'")

class MetasploitInput(GeminiSafeModel):
    target: str = Field(description="Target IP/host")
    action: str = Field(default="search", description="Action: search, check, exploit (exploit requires CVE reference)")
    search_query: str = Field(default="", description="Search query for modules (must include CVE for exploit action)")
    module: str = Field(default="", description="Exploit module path (must reference a CVE)")

class CustomExploitInput(GeminiSafeModel):
    """Schema for AI-generated Python exploit code execution."""
    target: str = Field(description="Target URL/host to exploit")
    exploit_code: str = Field(description="Python exploit code to execute in sandbox")
    description: str = Field(default="", description="Brief description of what this exploit does")
    vuln_type: str = Field(default="", description="Vulnerability type: xss, sqli, ssrf, rce, lfi, redirect, crlf, etc.")


# ─── Agent Tools ────────────────────────────────────────────

class AddFindingInput(GeminiSafeModel):
    """Schema for the add_finding LangChain tool."""
    title: str = Field(description="Finding title (e.g. 'SQL Injection in login page')")
    severity: str = Field(description="Severity: critical, high, medium, low, info")
    affected_url: str = Field(default="", description="Affected URL")
    affected_host: str = Field(default="", description="Affected host/IP")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Evidence (curl command, output, etc.)")
    remediation: str = Field(default="", description="How to fix this vulnerability")
    category: str = Field(default="", description="Category: sqli, xss, rce, etc.")
    tool_source: str = Field(default="", description="Tool that found this")


class EmailSecurityInput(GeminiSafeModel):
    """Schema for email security checks (SPF, DKIM, DMARC, MX, DNSBL)."""
    target: str = Field(description="Domain to check email security for, e.g. 'example.com'")
    dkim_selector: str = Field(default="default", description="DKIM selector to check (e.g. 'google', 'mail', 'default')")
