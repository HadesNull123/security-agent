"""
Pydantic data models for the Security Agent.
Defines structured types for targets, scan results, findings, and reports.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.core.config import Severity, ScanPhase


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    CIDR = "cidr"


class Target(BaseModel):
    """A scan target (domain, IP, URL, or CIDR range)."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    value: str  # e.g. "example.com", "192.168.1.0/24"
    target_type: TargetType
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Reconnaissance Results
# ---------------------------------------------------------------------------

class Subdomain(BaseModel):
    """Discovered subdomain."""
    host: str
    source: str = ""  # tool that found it
    ip_addresses: list[str] = Field(default_factory=list)
    cnames: list[str] = Field(default_factory=list)


class PortInfo(BaseModel):
    """Open port information."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class HostInfo(BaseModel):
    """Aggregated host reconnaissance data."""
    host: str
    ip: str = ""
    ports: list[PortInfo] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    os_info: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class URLInfo(BaseModel):
    """Discovered URL from crawling."""
    url: str
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    source: str = ""  # tool that found it


class ReconResult(BaseModel):
    """Aggregated reconnaissance results."""
    target: Target
    subdomains: list[Subdomain] = Field(default_factory=list)
    hosts: list[HostInfo] = Field(default_factory=list)
    urls: list[URLInfo] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Vulnerability / Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A discovered vulnerability or security issue."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    confidence: str = "medium"  # low, medium, high, confirmed
    category: str = ""  # e.g. "SQLi", "XSS", "RCE"
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    affected_url: str = ""
    affected_host: str = ""
    affected_port: int | None = None
    evidence: str = ""  # proof / raw output
    remediation: str = ""
    tool_source: str = ""  # which tool found it
    references: list[str] = Field(default_factory=list)
    extra_data: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Exploitation
# ---------------------------------------------------------------------------

class ExploitResult(BaseModel):
    """Result of an exploitation attempt."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str  # links back to the Finding
    tool_used: str
    payload: str = ""
    success: bool = False
    output: str = ""
    access_gained: str = ""  # e.g. "shell", "data_dump", "file_read"
    data_extracted: dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Tool Execution
# ---------------------------------------------------------------------------

class ToolExecution(BaseModel):
    """Record of a tool execution."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    command: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    phase: ScanPhase
    status: str = "pending"  # pending, running, completed, failed, timeout
    output: str = ""
    error: str = ""
    duration_seconds: float = 0.0
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Scan Session
# ---------------------------------------------------------------------------

class ScanSession(BaseModel):
    """A complete scan session."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    targets: list[Target] = Field(default_factory=list)
    recon_results: list[ReconResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    exploit_results: list[ExploitResult] = Field(default_factory=list)
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    status: str = "initialized"  # initialized, running, completed, failed
    current_phase: ScanPhase = ScanPhase.RECON
    scan_mode: str = "normal"  # quick, normal, deep
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    @property
    def severity_summary(self) -> dict[str, int]:
        """Count findings by severity."""
        summary: dict[str, int] = {}
        for f in self.findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1
        return summary

    @property
    def total_findings(self) -> int:
        return len(self.findings)
