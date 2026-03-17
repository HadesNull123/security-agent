"""
Security Agent Orchestrator - The AI brain that coordinates the full penetration testing pipeline.
Uses LangChain to connect LLM with security tools and manage the scan workflow.

Enhanced with:
- Findings parser: automatically extracts Finding objects from tool outputs
- add_finding tool: LLM can register findings directly
- Vector memory: context recall across phases
- Output filtering: adaptive token limits per tool
- Skills system: AI-guided tool selection
- Scan modes: quick/normal/deep
- Token budget tracking with graceful stop
- Auto-install for missing tools
- Lazy LLM init: only connect when needed
- Concurrent recon: run independent tools in parallel
- Separate memory DB to avoid lock conflicts
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from langchain.agents import AgentExecutor, create_tool_calling_agent
except ImportError:
    from langchain.agents.agent import AgentExecutor
    from langchain.agents.tool_calling_agent.base import create_tool_calling_agent
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from src.core.config import Config, ScanPhase, Severity
from src.core.database import Database
from src.scanner.findings_parser import FindingsParser
from src.scanner.installer import ToolInstaller
from src.agent.memory import VectorMemory
from src.core.models import Finding, ScanSession, Target, TargetType, ToolExecution
from src.scanner.output_filter import OutputFilter
from src.agent.prompts import (
    ANALYSIS_PROMPT,
    ENRICHMENT_PROMPT,
    EXPLOITATION_PROMPT,
    RECON_PROMPT,
    REPORTING_PROMPT,
    SCANNING_PROMPT,
    SYSTEM_PROMPT,
)
from src.security.safety import SafetyGuard
from src.agent.skills import get_skills_prompt, get_scan_mode_guidance
from src.tools import ToolResult
from src.tools.recon import (
    AmassTool,
    HttpxTool,
    KatanaTool,
    NaabuTool,
    SubfinderTool,
    Wafw00fTool,
    WhatWebTool,
    DnsxTool,
)
from src.tools.scanner import (
    AcunetixTool,
    FfufTool,
    GobusterTool,
    NiktoTool,
    NucleiTool,
    SecretScannerTool,
    TestSSLTool,
    ZAPTool,
)
from src.tools.exploit import (
    CommixTool,
    CustomExploitTool,
    MetasploitTool,
    SearchSploitTool,
    SQLMapTool,
)
from src.ui.console import ScanUI

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Token Budget Tracking
# ─────────────────────────────────────────────────────────────

# Retryable error patterns (Gemini 503, rate limits, overload)
_RETRYABLE_PATTERNS = (
    "503", "429", "overloaded", "high demand",
    "rate limit", "quota", "resource exhausted",
    "temporarily unavailable", "try again",
)


def _is_retryable_error(error: Exception) -> bool:
    """Check if an error is a transient API error worth retrying."""
    error_str = str(error).lower()
    return any(p in error_str for p in _RETRYABLE_PATTERNS)


async def _llm_retry(coro_factory, max_retries: int = 3, initial_wait: int = 30):
    """
    Retry an async LLM call with exponential backoff.

    Args:
        coro_factory: A callable that returns a new coroutine each time (lambda: llm.ainvoke(...))
        max_retries: Maximum retry attempts
        initial_wait: Seconds to wait before first retry (doubles each retry)

    Returns:
        The result of the successful coroutine

    Raises:
        The last exception if all retries are exhausted
    """
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            return await coro_factory()
        except Exception as e:
            last_error = e
            if attempt < max_retries and _is_retryable_error(e):
                wait_time = initial_wait * (2 ** attempt)
                logger.warning(
                    f"⏳ LLM API error (attempt {attempt + 1}/{max_retries + 1}): {str(e)[:100]}. "
                    f"Retrying in {wait_time}s..."
                )
                await asyncio.sleep(wait_time)
            else:
                raise
    raise last_error


class TokenBudgetExhausted(Exception):
    """Raised when the agent runs out of token budget."""
    pass


class TokenTracker:
    """Tracks approximate token usage and enforces budget limits."""

    def __init__(self, max_tokens: int = 500_000):
        self.max_tokens = max_tokens
        self.tokens_used = 0
        self.calls_made = 0

    def track(self, text: str) -> None:
        estimated = len(text) // 3
        self.tokens_used += estimated
        self.calls_made += 1

    def check_budget(self) -> None:
        if self.tokens_used >= self.max_tokens:
            raise TokenBudgetExhausted(
                f"Token budget exhausted: {self.tokens_used:,}/{self.max_tokens:,} tokens used "
                f"across {self.calls_made} LLM calls. Stopping gracefully."
            )

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    @property
    def usage_percent(self) -> float:
        return (self.tokens_used / self.max_tokens) * 100 if self.max_tokens > 0 else 100


# ─────────────────────────────────────────────────────────────
# Pydantic schemas for LangChain tool input validation
# ─────────────────────────────────────────────────────────────

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

class NiktoInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with Nikto")
    tuning: str = Field(default="", description="Scan tuning: 1=file upload, 2=misconfig, 3=info, 4=injection, etc.")

class TestSSLInput(GeminiSafeModel):
    target: str = Field(description="Host:port to test SSL/TLS (e.g. example.com:443)")
    checks: str = Field(default="", description="Specific checks: --protocols, --ciphers, --vulnerabilities")

class NucleiInput(GeminiSafeModel):
    target: str = Field(description="URL to scan for vulnerabilities")
    tags: str = Field(default="", description="Template tags, e.g. 'cve,sqli,xss'")
    severity: str = Field(default="", description="Severity filter: critical,high,medium,low,info")
    rate_limit: int = Field(default=0, description="Requests per second (0=default)")

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

class ZAPInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with ZAP")
    scan_type: str = Field(default="spider_and_active", description="Type: spider, active, spider_and_active")

class SecretScannerInput(GeminiSafeModel):
    target: str = Field(default="", description="Domain or URL to auto-crawl and scan for leaked credentials in JS/CSS/HTML files.")
    urls: str = Field(default="", description="Comma-separated list of specific URLs to scan. If empty, will auto-crawl the target.")

class AcunetixInput(GeminiSafeModel):
    target: str = Field(description="URL to scan with Acunetix")
    profile: str = Field(default="full", description="Scan profile: full, high_risk, xss, sqli")

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


class SecurityAgent:
    """
    Main AI Agent orchestrator. Manages the full pentesting pipeline
    using LangChain to connect the LLM with security tools.
    """

    def __init__(self, config: Config):
        self.config = config
        self._llm = None  # Lazy init
        self.safety = SafetyGuard(
            allowed_scope=config.agent.allowed_scope,
            safe_mode=config.agent.safe_mode,
        )
        self.db = Database(config.agent.database_path)
        # Bug #3 fix: Use separate DB file for memory to avoid lock conflicts
        memory_db_path = config.agent.database_path.replace(".db", "_memory.db")
        self.memory = VectorMemory(memory_db_path)
        self.output_filter = OutputFilter()
        self.findings_parser = FindingsParser()
        self.token_tracker = TokenTracker()
        self.installer = ToolInstaller()
        self.session: ScanSession | None = None
        self.context: dict[str, Any] = {}
        self.scan_mode: str = "normal"
        self.ui: ScanUI | None = None

        # Initialize tool instances (skip unconfigured ones)
        self._init_tools()

    @property
    def llm(self):
        """Lazy LLM init: only connect when first needed."""
        if self._llm is None:
            from src.agent.llm_factory import create_llm
            self._llm = create_llm(self.config)
            logger.info(f"LLM initialized: {self.config.llm.provider.value}/{self.config.llm.model}")
        return self._llm

    def _init_tools(self) -> None:
        """Initialize available tool instances."""
        self.recon_tools: dict[str, Any] = {
            "subfinder": SubfinderTool(),
            "naabu": NaabuTool(),
            "katana": KatanaTool(),
            "httpx": HttpxTool(),
            "amass": AmassTool(),
            "whatweb": WhatWebTool(),
            "wafw00f": Wafw00fTool(),
            "dnsx": DnsxTool(),
        }

        self.scanner_tools: dict[str, Any] = {
            "nuclei": NucleiTool(),
            "ffuf": FfufTool(),
            "gobuster": GobusterTool(),
            "nikto": NiktoTool(),
            "testssl": TestSSLTool(),
            "secret_scanner": SecretScannerTool(),
        }
        if self.config.zap.api_key:
            self.scanner_tools["zap"] = ZAPTool(self.config.zap)
        else:
            logger.info("ℹ️ ZAP not configured (set ZAP_API_KEY in .env)")

        if self.config.acunetix.api_url and self.config.acunetix.api_key:
            self.scanner_tools["acunetix"] = AcunetixTool(self.config.acunetix)
        else:
            logger.warning(
                "⚠️ Acunetix NOT registered — need ACUNETIX_API_URL and ACUNETIX_API_KEY in .env. "
                f"Current: api_url={bool(self.config.acunetix.api_url)}, api_key={bool(self.config.acunetix.api_key)}"
            )

        self.exploit_tools: dict[str, Any] = {
            "sqlmap": SQLMapTool(),
            "commix": CommixTool(),
            "searchsploit": SearchSploitTool(),
            "custom_exploit": CustomExploitTool(safety_guard=self.safety),
        }
        if self.config.metasploit.rpc_password:
            self.exploit_tools["metasploit"] = MetasploitTool(self.config.metasploit)
        else:
            logger.info("ℹ️ Metasploit not configured (set MSF_RPC_PASS in .env)")

    def _get_available_tools(self, tool_dict: dict[str, Any]) -> dict[str, Any]:
        available = {}
        unavailable = []
        for name, tool in tool_dict.items():
            if tool.is_available():
                available[name] = tool
            else:
                unavailable.append(name)
        if unavailable:
            logger.warning(
                f"⚠️ Tools NOT available (not installed or not configured): "
                f"{', '.join(unavailable)}"
            )
        logger.info(
            f"✅ Available tools ({len(available)}): {', '.join(available.keys()) or 'NONE'}"
        )
        return available

    async def _auto_install_missing(self) -> dict[str, tuple[bool, str]]:
        all_names = list(self.recon_tools.keys()) + list(self.scanner_tools.keys()) + list(self.exploit_tools.keys())
        cli_names = [n for n in all_names if n not in ("zap", "acunetix", "metasploit", "custom_exploit")]
        missing = self.installer.get_missing_tools(cli_names)
        if not missing:
            return {}
        logger.info(f"Auto-installing missing tools: {missing}")
        return await self.installer.install_all_missing(missing)

    # ─── Core tool wrapper with findings extraction ──────────

    def _safe_tool_run(self, tool_instance, tool_name: str):
        """Wrapper: safety check → run → filter output → auto-parse findings → store memory → track tokens."""

        async def wrapper(**kwargs) -> str:
            try:
                self.token_tracker.check_budget()
            except TokenBudgetExhausted as e:
                return f"⚠️ TOKEN BUDGET EXHAUSTED: {str(e)}"

            target = kwargs.get("target", kwargs.get("query", ""))

            try:
                self.safety.check_all(target, tool_name, kwargs)
            except Exception as e:
                return f"🔒 SAFETY BLOCK: {str(e)}"

            # UI: tool started
            if self.ui:
                self.ui.tool_start(tool_name)

            result: ToolResult = await tool_instance.run(**kwargs)

            # UI: tool completed + stream key output to tool panel
            if self.ui:
                summary = ""
                if result.success and result.data:
                    count = result.data.get("count", result.data.get("total", ""))
                    summary = f"{count} results" if count else "OK"
                    # Stream key output lines to the tool's panel
                    data = result.data
                    if "subdomains" in data:
                        for sd in data["subdomains"][:5]:
                            self.ui.tool_output(tool_name, f"  {sd}")
                        if data.get("count", 0) > 5:
                            self.ui.tool_output(tool_name, f"  ... +{data['count'] - 5} more")
                    elif "urls" in data:
                        for u in data["urls"][:5]:
                            url = u["url"] if isinstance(u, dict) else str(u)
                            self.ui.tool_output(tool_name, f"  {url[:100]}")
                        if data.get("count", 0) > 5:
                            self.ui.tool_output(tool_name, f"  ... +{data['count'] - 5} more")
                    elif "hosts" in data:
                        for h in data["hosts"][:5]:
                            self.ui.tool_output(tool_name, f"  {h}")
                    elif "ports" in data:
                        ports_list = data["ports"]
                        if isinstance(ports_list, list):
                            ports_str = ", ".join(str(p.get("port", p) if isinstance(p, dict) else p) for p in ports_list[:10])
                            self.ui.tool_output(tool_name, f"  Ports: {ports_str}")
                    elif "leaks_found" in data:
                        self.ui.tool_output(tool_name, f"  Leaks: {data['leaks_found']}")
                        for leak in data.get("findings", [])[:3]:
                            self.ui.tool_output(tool_name, f"  🔑 {leak.get('key_type', '')[:40]}")
                    elif "vulnerabilities" in data:
                        for v in data["vulnerabilities"][:5]:
                            sev = v.get("severity", v.get("info", {}).get("severity", "?"))
                            name = v.get("vt_name", v.get("info", {}).get("name", v.get("name", "")))[:50]
                            self.ui.tool_output(tool_name, f"  [{sev}] {name}")
                    elif "technologies" in data:
                        for t in data["technologies"][:5]:
                            self.ui.tool_output(tool_name, f"  {t}")
                    elif isinstance(data.get("results"), list):
                        for r in data["results"][:5]:
                            self.ui.tool_output(tool_name, f"  {str(r)[:80]}")
                    else:
                        self.ui.tool_output(tool_name, f"  {summary}")
                elif not result.success:
                    summary = result.error[:40] if result.error else "Failed"
                    self.ui.tool_output(tool_name, f"[red]{summary}[/red]")
                self.ui.tool_complete(tool_name, success=result.success, result_summary=summary)

            # Log execution to database
            if self.session:
                execution = tool_instance.to_execution_record(result)
                await self.db.save_tool_execution(self.session.id, execution)
                self.session.tool_executions.append(execution)

            # ★ Auto-parse findings from tool output (data first, raw_output fallback)
            if self.session and result.success:
                parsed_findings = []
                if result.data:
                    parsed_findings = self.findings_parser.parse_tool_result(tool_name, result.data)
                if not parsed_findings and result.raw_output and tool_name in ("nuclei", "zap", "sqlmap", "commix", "ffuf", "gobuster"):
                    # B2 fix: Try parsing raw_output as fallback
                    try:
                        import json as _json
                        raw_data = _json.loads(result.raw_output)
                        if isinstance(raw_data, dict):
                            parsed_findings = self.findings_parser.parse_tool_result(tool_name, raw_data)
                    except (ValueError, TypeError):
                        pass
                for finding in parsed_findings:
                    self.session.findings.append(finding)
                    await self.db.save_finding(self.session.id, finding)
                    logger.info(f"📋 Auto-parsed finding: [{finding.severity.value.upper()}] {finding.title}")

            # Filter output for LLM
            summary = self.output_filter.summarize_tool_result(
                tool_name, result.data, result.raw_output
            )

            # Store in vector memory
            if self.session and result.success:
                self.memory.store(
                    content=summary,
                    category=f"tool_output_{tool_instance.phase.value}",
                    session_id=self.session.id,
                    metadata={"tool": tool_name, "target": target},
                )

            self.token_tracker.track(summary)
            return summary

        return wrapper

    def _add_finding_fn(self):
        """Create the add_finding tool function that lets LLM register findings directly."""

        async def add_finding(
            title: str,
            severity: str,
            affected_url: str = "",
            affected_host: str = "",
            description: str = "",
            evidence: str = "",
            remediation: str = "",
            category: str = "",
            tool_source: str = "",
        ) -> str:
            if not self.session:
                return "❌ No active session."

            try:
                sev = Severity(severity.lower())
            except ValueError:
                sev = Severity.INFO

            finding = Finding(
                title=title,
                description=description,
                severity=sev,
                confidence="high" if sev in (Severity.CRITICAL, Severity.HIGH) else "medium",
                category=category,
                affected_url=affected_url,
                affected_host=affected_host,
                evidence=evidence,
                remediation=remediation,
                tool_source=tool_source or "ai_analysis",
            )

            # Dedup check
            if self.findings_parser.is_duplicate(finding):
                return f"⚠️ Duplicate finding skipped: {title}"

            self.session.findings.append(finding)
            await self.db.save_finding(self.session.id, finding)
            logger.info(f"📋 Finding added by AI: [{sev.value.upper()}] {title}")

            # UI: finding added
            if self.ui:
                self.ui.add_finding(sev.value, title)

            return f"✅ Finding registered: [{sev.value.upper()}] {title} | Total findings: {len(self.session.findings)}"

        return add_finding

    # ─── Build LangChain tools ───────────────────────────────

    def _build_langchain_tools(self, phase: ScanPhase) -> list[StructuredTool]:
        tools = []
        tool_map: dict[str, tuple] = {}

        if phase == ScanPhase.RECON:
            available = self._get_available_tools(self.recon_tools)
            schema_map = {
                "subfinder": SubfinderInput, "naabu": NaabuInput,
                "katana": KatanaInput, "httpx": HttpxInput,
                "amass": AmassInput,
                "whatweb": WhatWebInput, "wafw00f": Wafw00fInput,
                "dnsx": DnsxInput,
            }
            tool_map = {n: (available[n], schema_map[n]) for n in available if n in schema_map}

        elif phase == ScanPhase.SCANNING:
            available = self._get_available_tools(self.scanner_tools)
            schema_map = {
                "nuclei": NucleiInput, "ffuf": FfufInput,
                "gobuster": GobusterInput, "zap": ZAPInput,
                "acunetix": AcunetixInput,
                "nikto": NiktoInput, "testssl": TestSSLInput,
                "secret_scanner": SecretScannerInput,
            }
            tool_map = {n: (available[n], schema_map[n]) for n in available if n in schema_map}

        elif phase == ScanPhase.EXPLOITATION:
            available = self._get_available_tools(self.exploit_tools)
            schema_map = {
                "sqlmap": SQLMapInput, "commix": CommixInput,
                "searchsploit": SearchSploitInput, "metasploit": MetasploitInput,
                "custom_exploit": CustomExploitInput,
            }
            tool_map = {n: (available[n], schema_map[n]) for n in available if n in schema_map}

        for name, (instance, schema) in tool_map.items():
            safe_fn = self._safe_tool_run(instance, name)
            tools.append(StructuredTool.from_function(
                coroutine=safe_fn,
                name=name,
                description=instance.description,
                args_schema=schema,
            ))

        # ★ Add the add_finding tool for scanning/exploitation/analysis phases
        if phase in (ScanPhase.SCANNING, ScanPhase.EXPLOITATION):
            tools.append(StructuredTool.from_function(
                coroutine=self._add_finding_fn(),
                name="add_finding",
                description=(
                    "Register a security finding/vulnerability. Use this after discovering a "
                    "vulnerability from tool output. Provide title, severity (critical/high/medium/low/info), "
                    "affected URL, description, evidence, and remediation."
                ),
                args_schema=AddFindingInput,
            ))

        return tools

    def _build_agent_executor(self, phase: ScanPhase) -> AgentExecutor | None:
        tools = self._build_langchain_tools(phase)

        if not tools:
            logger.warning(f"No tools available for phase {phase.value}. Skipping.")
            return None

        # Log registered tools for debugging
        tool_names = [t.name for t in tools]
        logger.info(f"Phase {phase.value}: registering {len(tools)} tools: {', '.join(tool_names)}")

        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        agent = create_tool_calling_agent(self.llm, tools, prompt)

        # Use user-selected scan intensity for max_iterations
        max_iter = getattr(self, 'scan_intensity', 20)

        return AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=max_iter,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
            early_stopping_method="force",
        )

    # ─── Lifecycle ───────────────────────────────────────────

    async def initialize(self) -> None:
        await self.db.connect()
        self.memory.connect()

        # ★ Step 1: Auto-update tools from GitHub Releases (fast, no Go needed)
        try:
            from src.scanner.updater import updater
            logger.info("🔄 Checking for tool updates from GitHub Releases...")
            update_results = await updater.update_all()
            for tool_name, (success, msg) in update_results.items():
                if success:
                    logger.info(f"  ✅ {tool_name}: {msg}")
                else:
                    logger.warning(f"  ⚠️ {tool_name}: {msg}")
        except Exception as e:
            logger.warning(f"Auto-update check failed (continuing anyway): {e}")

        # ★ Step 2: Fallback — install any still-missing tools via go/pip/apt
        install_results = await self._auto_install_missing()
        for tool_name, (success, msg) in install_results.items():
            if success:
                logger.info(f"✅ {tool_name}: {msg}")
            else:
                logger.warning(f"⚠️ {tool_name}: {msg}")

    async def close(self) -> None:
        await self.db.close()
        self.memory.close()

    # ─── Main scan pipeline ──────────────────────────────────

    async def scan(
        self,
        targets: list[str],
        target_type: str = "domain",
        mode: str = "normal",
        scan_intensity: int = 20,
    ) -> ScanSession:
        self.scan_mode = mode
        self.scan_intensity = scan_intensity
        await self.initialize()

        try:
            tt = TargetType(target_type)
        except ValueError:
            tt = TargetType.DOMAIN
        target_objs = [Target(value=t, target_type=tt) for t in targets]
        self.session = ScanSession(targets=target_objs)
        await self.db.create_session(self.session)

        # Start live UI
        self.ui = ScanUI(targets=targets, mode=mode)
        self.ui.start()

        logger.info(
            f"Starting scan session {self.session.id} | "
            f"Mode: {mode.upper()} | Targets: {targets}"
        )

        try:
            # Phase 1: Recon
            await self._run_phase(ScanPhase.RECON, targets)

            # ★ Extract context from recon tool outputs for use in SCANNING prompt
            self._extract_recon_context()

            # Phase 2: Scanning
            await self._run_phase(ScanPhase.SCANNING, targets)

            # Phase 3: Analysis (LLM-only)
            await self._run_analysis(targets)

            # Phase 4: Exploitation (runs at ALL levels if there are findings)
            if self.session.findings:
                await self._run_phase(ScanPhase.EXPLOITATION, targets)
            else:
                logger.info("Skipping exploitation — no findings to exploit")

            # Phase 5: Report
            if self.ui:
                self.ui.set_phase("reporting")
            await self._generate_report(targets)

            self.session.status = "completed"
            self.session.completed_at = datetime.utcnow()
            await self.db.complete_session(self.session.id)

            # Stop UI
            if self.ui:
                self.ui.phase_complete("reporting")
                self.ui.stop()
                self.ui = None

            logger.info(
                f"✅ Scan completed. "
                f"Findings: {len(self.session.findings)} | "
                f"Tokens: ~{self.token_tracker.tokens_used:,}"
            )
            return self.session

        except TokenBudgetExhausted as e:
            logger.warning(f"⚠️ {str(e)}")
            self.session.status = "partial"
            if self.ui:
                self.ui.log("⚠️ Token budget exhausted — generating partial report")
                self.ui.stop()
                self.ui = None
            try:
                await self._generate_report(targets)
            except Exception:
                pass
            await self.db.update_session_status(self.session.id, "partial")
            return self.session

        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            # B3 fix: Check session exists before updating status
            if self.session:
                self.session.status = "failed"
                try:
                    await self.db.update_session_status(self.session.id, "failed")
                except Exception:
                    pass
            raise

        finally:
            # Always stop UI
            if self.ui:
                self.ui.stop()
                self.ui = None
            await self.close()

    async def _run_phase(self, phase: ScanPhase, targets: list[str]) -> None:
        logger.info(f"═══ Phase: {phase.value.upper()} ═══")
        self.session.current_phase = phase
        await self.db.update_session_status(self.session.id, "running", phase.value)

        # UI: phase update + register all available tools for grid
        if self.ui:
            self.ui.set_phase(phase.value)
            # Register tools for multi-panel grid
            if phase == ScanPhase.RECON:
                avail = list(self._get_available_tools(self.recon_tools).keys())
            elif phase == ScanPhase.SCANNING:
                avail = list(self._get_available_tools(self.scanner_tools).keys())
            elif phase == ScanPhase.EXPLOITATION:
                avail = list(self._get_available_tools(self.exploit_tools).keys())
            else:
                avail = []
            if avail:
                self.ui.register_phase_tools(avail)

        self.token_tracker.check_budget()

        executor = self._build_agent_executor(phase)
        if executor is None:
            logger.warning(f"Skipping phase {phase.value} - no tools available.")
            return

        prompt_text = self._build_phase_prompt(phase, targets)
        self.token_tracker.track(prompt_text)

        try:
            result = await _llm_retry(
                lambda: executor.ainvoke({
                    "input": prompt_text,
                    "chat_history": [],
                }),
                max_retries=3,
                initial_wait=30,
            )
            output = result.get("output", "")
            self.context[phase.value] = output
            self.token_tracker.track(output)

            # ★ Track which tools were actually called in this phase
            intermediate_steps = result.get("intermediate_steps", [])
            tools_called = set()
            for step in intermediate_steps:
                if hasattr(step[0], 'tool'):
                    tools_called.add(step[0].tool)
            
            # Get available tools for comparison
            if phase == ScanPhase.RECON:
                avail_names = set(self._get_available_tools(self.recon_tools).keys())
            elif phase == ScanPhase.SCANNING:
                avail_names = set(self._get_available_tools(self.scanner_tools).keys())
            elif phase == ScanPhase.EXPLOITATION:
                avail_names = set(self._get_available_tools(self.exploit_tools).keys())
            else:
                avail_names = set()

            missed_tools = avail_names - tools_called - {"add_finding"}
            if missed_tools:
                logger.warning(
                    f"⚠️ Phase {phase.value}: {len(missed_tools)} tools NOT called: "
                    f"{', '.join(sorted(missed_tools))}"
                )
            logger.info(
                f"Phase {phase.value}: called {len(tools_called)} tools "
                f"({', '.join(sorted(tools_called))}) | "
                f"available: {len(avail_names)} | "
                f"iterations used: {len(intermediate_steps)}"
            )

            # ★ AUTO-RETRY: If too many tools were skipped, re-run with explicit instructions
            retry_count = 0
            max_retries = 2
            while missed_tools and retry_count < max_retries:
                retry_count += 1
                missed_list = ", ".join(sorted(missed_tools))
                logger.warning(
                    f"🔄 Phase {phase.value}: Retrying to run {len(missed_tools)} missed tools "
                    f"(attempt {retry_count}/{max_retries}): {missed_list}"
                )

                retry_prompt = (
                    f"CRITICAL: You DID NOT call these tools in the previous run: {missed_list}\n\n"
                    f"You MUST call each of these tools NOW, one by one:\n"
                )
                for tool_name in sorted(missed_tools):
                    retry_prompt += f"- {tool_name}: CALL THIS TOOL NOW\n"
                retry_prompt += (
                    f"\nTarget: {', '.join(targets)}\n"
                    f"Do NOT summarize. Do NOT give a final answer.\n"
                    f"START by calling the first tool in the list above.\n"
                )

                # Re-build executor for retry
                retry_executor = self._build_agent_executor(phase)
                if retry_executor is None:
                    break

                try:
                    _rp = retry_prompt  # Capture by value for lambda
                    retry_result = await _llm_retry(
                        lambda _rp=_rp: retry_executor.ainvoke({
                            "input": _rp,
                            "chat_history": [],
                        }),
                        max_retries=2,
                        initial_wait=15,
                    )
                    retry_output = retry_result.get("output", "")
                    self.context[phase.value] += "\n" + retry_output

                    # Track newly called tools
                    retry_steps = retry_result.get("intermediate_steps", [])
                    for step in retry_steps:
                        if hasattr(step[0], 'tool'):
                            tools_called.add(step[0].tool)

                    # Update missed tools
                    missed_tools = avail_names - tools_called - {"add_finding"}
                    logger.info(
                        f"Phase {phase.value} retry {retry_count}: "
                        f"now called {len(tools_called)} tools | "
                        f"still missed: {len(missed_tools)}"
                    )

                except Exception as e:
                    logger.error(f"Phase {phase.value} retry {retry_count} failed: {e}")
                    break

            self.memory.store(
                content=output[:5000],
                category=f"phase_result_{phase.value}",
                session_id=self.session.id,
            )

            # UI: phase complete + token update
            if self.ui:
                self.ui.phase_complete(phase.value)
                self.ui.update_tokens(self.token_tracker.tokens_used)

            logger.info(
                f"Phase {phase.value} completed. "
                f"Findings so far: {len(self.session.findings)} | "
                f"Tokens: ~{self.token_tracker.tokens_used:,}"
            )

        except TokenBudgetExhausted:
            raise
        except Exception as e:
            logger.error(f"Phase {phase.value} failed after retries: {e}")
            self.context[phase.value] = f"Phase failed: {str(e)}"

    def _extract_recon_context(self) -> None:
        """Extract structured data from saved tool output JSON files to populate context for SCANNING prompt."""
        import os
        import glob

        technologies = []
        ports = []
        urls_count = 0

        output_dir = os.path.join(".", "data", "tool_outputs", "latest")
        if not os.path.exists(output_dir):
            logger.warning("No tool output directory found for recon context extraction")
            return

        for filepath in sorted(glob.glob(os.path.join(output_dir, "*.json"))):
            try:
                with open(filepath) as f:
                    file_data = json.load(f)

                tool_name = file_data.get("tool", "")
                if not file_data.get("success", False):
                    continue

                data = file_data.get("data", {})
                if not isinstance(data, dict):
                    continue

                # Technologies from whatweb/httpx
                if tool_name in ("whatweb", "httpx"):
                    for key in ("technologies", "tech"):
                        techs = data.get(key, [])
                        if isinstance(techs, list):
                            for t in techs:
                                if isinstance(t, dict):
                                    technologies.append(t.get("name", str(t)))
                                else:
                                    technologies.append(str(t))

                # Ports from naabu
                if tool_name == "naabu":
                    port_list = data.get("ports", [])
                    if isinstance(port_list, list):
                        for p in port_list:
                            if isinstance(p, dict):
                                ports.append(f"{p.get('host', '')}:{p.get('port', '')}")
                            else:
                                ports.append(str(p))

                # URLs from katana
                if tool_name == "katana":
                    urls_count += data.get("count", 0)

                # Subdomains from subfinder
                if tool_name == "subfinder":
                    sub_count = data.get("count", 0)
                    if sub_count:
                        self.context["subdomains_count"] = sub_count

            except Exception as e:
                logger.debug(f"Could not parse tool output {filepath}: {e}")
                continue

        # Deduplicate and store
        self.context["technologies"] = ", ".join(sorted(set(technologies))) if technologies else "Unknown"
        self.context["ports"] = ", ".join(sorted(set(ports))) if ports else "Not scanned"
        self.context["urls_count"] = urls_count

        logger.info(
            f"Recon context extracted: technologies={self.context['technologies'][:100]}, "
            f"ports={self.context['ports'][:100]}, urls={urls_count}"
        )

    def _build_phase_prompt(self, phase: ScanPhase, targets: list[str]) -> str:
        target_str = ", ".join(targets)

        if phase == ScanPhase.RECON:
            all_tools = self.recon_tools
            available_tools = list(self._get_available_tools(self.recon_tools).keys())
        elif phase == ScanPhase.SCANNING:
            all_tools = self.scanner_tools
            available_tools = list(self._get_available_tools(self.scanner_tools).keys())
            # Always add add_finding
            available_tools.append("add_finding")
        elif phase == ScanPhase.EXPLOITATION:
            all_tools = self.exploit_tools
            available_tools = list(self._get_available_tools(self.exploit_tools).keys())
            available_tools.append("add_finding")
        else:
            all_tools = {}
            available_tools = []

        # ★ Build explicit tool inventory for the AI
        tool_inventory = f"\n## 🔧 Available Tools ({len(available_tools)} ready)\n"
        for name, tool in all_tools.items():
            status = "✅" if name in available_tools else "❌ NOT INSTALLED"
            tool_inventory += f"- **{name}** [{status}]: {tool.description}\n"
        if "add_finding" in available_tools:
            tool_inventory += "- **add_finding** [✅]: Register a security finding/vulnerability\n"
        missing = [n for n in all_tools if n not in available_tools]
        if missing:
            tool_inventory += f"\n⚠️ {len(missing)} tools not installed: {', '.join(missing)}\n"
        tool_inventory += "\n⚠️ You MUST call EVERY tool marked ✅. Do NOT stop after 1-2 tools. Do NOT finish a phase without running ALL available tools.\n"

        skills_text = get_skills_prompt(phase.value, available_tools, scan_mode=self.scan_mode)
        mode_text = get_scan_mode_guidance(self.scan_mode)

        memory_context = self.memory.get_context(
            query=f"{phase.value} scan against {target_str}",
            max_tokens=1500,
            category=None,
        )

        budget_info = (
            f"\n⚡ Token Budget: ~{self.token_tracker.remaining:,} tokens remaining "
            f"({self.token_tracker.usage_percent:.0f}% used). Be efficient.\n"
        )

        # Current findings summary
        findings_info = ""
        if self.session and self.session.findings:
            findings_info = (
                f"\n📊 Current findings: {len(self.session.findings)} total | "
                f"{', '.join(f'{k}: {v}' for k, v in self.session.severity_summary.items() if v > 0)}\n"
            )

        if phase == ScanPhase.RECON:
            base_prompt = RECON_PROMPT.format(
                target=target_str,
                context=json.dumps(self.context, default=str)[:2000],
            )
        elif phase == ScanPhase.SCANNING:
            recon_ctx = self.context.get("recon", "No recon data available")
            base_prompt = SCANNING_PROMPT.format(
                target=target_str,
                recon_summary=str(recon_ctx)[:2000],
                technologies=self.context.get("technologies", "Unknown"),
                ports=self.context.get("ports", "Not scanned"),
                urls_count=self.context.get("urls_count", 0),
            )
        elif phase == ScanPhase.EXPLOITATION:
            base_prompt = EXPLOITATION_PROMPT.format(
                target=target_str,
                exploitable_findings=self._get_exploitable_findings_summary(),
                findings_detail=self._get_findings_detail(),
            )
        else:
            base_prompt = f"Continue the security assessment for {target_str}"

        full_prompt = f"{mode_text}\n{budget_info}{findings_info}\n{tool_inventory}\n{skills_text}\n"
        if memory_context:
            full_prompt += f"\n## Relevant Past Context\n{memory_context}\n"
        full_prompt += f"\n{base_prompt}"


        return full_prompt

    # ─── Analysis phase ──────────────────────────────────────

    async def _run_analysis(self, targets: list[str]) -> None:
        logger.info("═══ Phase: ANALYSIS ═══")
        self.session.current_phase = ScanPhase.ANALYSIS
        await self.db.update_session_status(self.session.id, "running", "analysis")

        # UI: analysis phase
        if self.ui:
            self.ui.set_phase("analysis")

        self.token_tracker.check_budget()

        # ★ Load all tool output files for comprehensive AI review
        tool_output_summaries = self._load_tool_output_files()

        # Include existing findings in analysis context
        existing_findings = self._get_findings_detail()
        scan_context = self.context.get("scanning", "No scan data")
        scan_context_filtered = self.output_filter.truncate_for_llm(str(scan_context))

        analysis_input = (
            f"Auto-parsed findings so far:\n{existing_findings}\n\n"
            f"Raw scan context:\n{scan_context_filtered}"
        )

        prompt = ANALYSIS_PROMPT.format(
            target=", ".join(t.value for t in self.session.targets),
            findings=analysis_input,
            tool_output_files=tool_output_summaries,
        )
        self.token_tracker.track(prompt)

        response = await _llm_retry(
            lambda: self.llm.ainvoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]),
            max_retries=3,
            initial_wait=30,
        )

        analysis_text = response.content if hasattr(response, "content") else str(response)
        self.context["analysis"] = analysis_text
        self.token_tracker.track(analysis_text)

        # ★ Parse findings from LLM analysis output
        llm_findings = self.findings_parser.parse_llm_analysis(analysis_text)
        for finding in llm_findings:
            if not self.findings_parser.is_duplicate(finding):
                self.session.findings.append(finding)
                await self.db.save_finding(self.session.id, finding)
                logger.info(f"📋 Finding from analysis: [{finding.severity.value.upper()}] {finding.title}")

        # ★ AI-enrich findings that lack detailed descriptions
        await self._ai_enrich_findings()

        self.memory.store(
            content=analysis_text[:5000],
            category="analysis",
            session_id=self.session.id,
        )

        logger.info(f"Analysis completed. Total findings: {len(self.session.findings)}")

    def _load_tool_output_files(self) -> str:
        """Load all saved tool output JSON files and return a summary for AI analysis."""
        import os
        import glob
        output_dir = os.path.join(".", "data", "tool_outputs", "latest")
        if not os.path.exists(output_dir):
            return "No tool output files found."

        summaries = []
        for filepath in sorted(glob.glob(os.path.join(output_dir, "*.json"))):
            try:
                with open(filepath) as f:
                    data = json.load(f)
                tool_name = data.get("tool", "unknown")
                success = data.get("success", False)
                exec_time = data.get("execution_time", 0)
                command = data.get("command", "")
                raw_preview = data.get("raw_output_preview", "")[:1500]
                error = data.get("error", "")

                summary = (
                    f"### {tool_name} ({'✅ SUCCESS' if success else '❌ FAILED'}) "
                    f"[{exec_time:.1f}s]\n"
                    f"Command: {command}\n"
                )
                if error:
                    summary += f"Error: {error}\n"
                if raw_preview:
                    summary += f"Output:\n```\n{raw_preview}\n```\n"
                summaries.append(summary)
            except Exception as e:
                logger.debug(f"Could not load tool output {filepath}: {e}")

        if not summaries:
            return "No tool output files found."

        return f"\n{'=' * 60}\n".join(summaries)

    async def _ai_enrich_findings(self) -> None:
        """Enrich findings that lack detailed AI analysis (description, remediation, impact)."""
        if not self.session or not self.session.findings:
            return

        findings_to_enrich = [
            f for f in self.session.findings
            if not f.description or len(f.description) < 50
            or not f.remediation or len(f.remediation) < 30
        ]

        if not findings_to_enrich:
            logger.info("All findings already have detailed descriptions.")
            return

        logger.info(f"Enriching {len(findings_to_enrich)} findings with AI analysis...")

        for finding in findings_to_enrich[:10]:  # Limit to 10 to avoid token waste
            try:
                self.token_tracker.check_budget()
            except TokenBudgetExhausted:
                logger.warning("Token budget exhausted during enrichment.")
                break

            try:
                finding_json = json.dumps(finding.model_dump(mode="json"), indent=2, default=str)
                # Get relevant tool output from memory
                raw_output = self.memory.search(
                    query=f"{finding.title} {finding.affected_url or finding.affected_host}",
                    top_k=2,
                )
                raw_output_text = "\n".join(r.get("content", "")[:500] for r in raw_output) if raw_output else "No raw output available"

                prompt = ENRICHMENT_PROMPT.format(
                    finding_json=finding_json,
                    raw_output=raw_output_text,
                )
                self.token_tracker.track(prompt)

                response = await _llm_retry(
                    lambda p=prompt: self.llm.ainvoke([
                        SystemMessage(content="You are an expert security analyst."),
                        HumanMessage(content=p),
                    ]),
                    max_retries=2,
                    initial_wait=15,
                )
                enrichment_text = response.content if hasattr(response, "content") else str(response)
                self.token_tracker.track(enrichment_text)

                # Parse enrichment response
                enrichment = self._parse_enrichment(enrichment_text)
                if enrichment:
                    if enrichment.get("description") and len(enrichment["description"]) > len(finding.description or ""):
                        finding.description = enrichment["description"]
                    if enrichment.get("remediation") and len(enrichment["remediation"]) > len(finding.remediation or ""):
                        finding.remediation = enrichment["remediation"]
                    if enrichment.get("cvss_score"):
                        finding.cvss_score = float(enrichment["cvss_score"])
                    if enrichment.get("references"):
                        finding.references = enrichment["references"]
                    # Store impact in description if available
                    if enrichment.get("impact") and enrichment["impact"] not in (finding.description or ""):
                        finding.description = (finding.description or "") + f"\n\n**Impact:** {enrichment['impact']}"

                    logger.info(f"✨ Enriched: {finding.title}")

            except Exception as e:
                logger.warning(f"Failed to enrich finding '{finding.title}': {e}")

    def _parse_enrichment(self, text: str) -> dict | None:
        """Extract JSON from AI enrichment response."""
        import re
        # Try to find JSON in code blocks
        json_match = re.search(r'```(?:json)?\s*\n?(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        # Try raw JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        return None

    def _get_exploitable_findings_summary(self) -> str:
        if not self.session or not self.session.findings:
            return "No confirmed findings to exploit."
        summary = []
        for f in self.session.findings:
            if f.severity.value in ("critical", "high"):
                summary.append(f"- [{f.severity.value.upper()}] {f.title} at {f.affected_url or f.affected_host}")
        return "\n".join(summary) if summary else "No high/critical findings to exploit."

    def _get_findings_detail(self) -> str:
        if not self.session or not self.session.findings:
            return "No findings."
        details = []
        for f in self.session.findings[:15]:  # Show more findings
            details.append(json.dumps(f.model_dump(mode="json"), indent=2, default=str))
        if len(self.session.findings) > 15:
            details.append(f"... and {len(self.session.findings) - 15} more findings")
        return "\n---\n".join(details)

    # ─── Reporting ───────────────────────────────────────────

    async def _generate_report(self, targets: list[str]) -> str:
        logger.info("═══ Generating Report ═══")
        report_dir = self.config.agent.report_output_dir
        Path(report_dir).mkdir(parents=True, exist_ok=True)

        # B5 fix: Use ReportGenerator (Jinja2) for structured markdown report
        try:
            from src.reporting.markdown import ReportGenerator
            reporter = ReportGenerator(report_dir)
            report_path = reporter.generate(self.session)
            logger.info(f"Report saved to: {report_path}")
            self.context["report_path"] = report_path

            # Also generate JSON report
            try:
                json_path = reporter.generate_json(self.session)
                logger.info(f"JSON report saved to: {json_path}")
                self.context["json_report_path"] = json_path
            except Exception as e:
                logger.warning(f"JSON report generation failed: {e}")
        except Exception as e:
            logger.warning(f"Jinja2 report failed, using LLM fallback: {e}")
            # Fallback: LLM-generated report
            prompt = REPORTING_PROMPT.format(
                target=", ".join(targets),
                total_findings=len(self.session.findings),
                severity_summary=json.dumps(self.session.severity_summary),
                tools_used=", ".join({te.tool_name for te in self.session.tool_executions}),
                exploit_summary=str(len(self.session.exploit_results)) + " attempts",
                all_findings=self._get_findings_detail(),
            )
            self.token_tracker.track(prompt)
            response = await self.llm.ainvoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ])
            report_text = response.content if hasattr(response, "content") else str(response)
            self.token_tracker.track(report_text)
            report_path = f"{report_dir}/report_{self.session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_path, "w") as f:
                f.write(report_text)
            self.context["report_path"] = report_path

        # Generate PDF report
        try:
            from src.reporting.pdf import generate_pdf_report
            pdf_path = generate_pdf_report(self.session, report_dir)
            logger.info(f"PDF report saved to: {pdf_path}")
            self.context["pdf_report_path"] = pdf_path
        except Exception as e:
            logger.warning(f"PDF report generation failed: {e}")

        return self.context.get("report_path", "")

    # ─── Public API ──────────────────────────────────────────

    def get_available_tools(self) -> dict[str, list[str]]:
        result = {}
        for category, tools_dict in [
            ("recon", self.recon_tools),
            ("scanner", self.scanner_tools),
            ("exploit", self.exploit_tools),
        ]:
            available = []
            for name, tool in tools_dict.items():
                status = "✅" if tool.is_available() else "❌"
                available.append(f"{status} {name}")
            result[category] = available
        return result
