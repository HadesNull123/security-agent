"""
Report generator using Jinja2 templates for professional penetration test reports.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from src.core.config import Severity
from src.core.models import ScanSession

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """# Penetration Testing Report

---

| Field | Value |
|-------|-------|
| **Report Date** | {{ report_date }} |
| **Session ID** | {{ session.id[:8] }} |
| **Targets** | {{ targets }} |
| **Status** | {{ session.status }} |
| **Duration** | {{ duration }} |

---

## 1. Executive Summary

A security assessment was conducted against **{{ targets }}**. The assessment identified **{{ total_findings }}** security {{ "finding" if total_findings == 1 else "findings" }}:

| Severity | Count |
|----------|-------|
{% for sev, count in severity_summary.items() %}| **{{ sev | upper }}** | {{ count }} |
{% endfor %}
{% if total_findings == 0 %}
No vulnerabilities were identified during the assessment. However, this does not guarantee the absence of security issues.
{% endif %}

## 2. Scope & Methodology

### Targets
{% for target in session.targets %}
- `{{ target.value }}` ({{ target.target_type.value }})
{% endfor %}

### Tools Used
{% for tool_name in tools_used %}
- {{ tool_name }}
{% endfor %}

### Methodology
The assessment followed a structured pipeline:
1. **Reconnaissance** - Subdomain enumeration, port scanning, web crawling
2. **Scanning** - Vulnerability scanning with Nuclei, directory discovery, API scanning
3. **Analysis** - AI-assisted analysis and deduplication of findings
4. **Exploitation** - Verification of exploitable vulnerabilities
5. **Reporting** - Automated report generation

## 3. Findings Summary

{% if findings %}
| # | Title | Severity | Confidence | Affected |
|---|-------|----------|------------|----------|
{% for f in findings %}| {{ loop.index }} | {{ f.title }} | **{{ f.severity.value | upper }}** | {{ f.confidence }} | `{{ f.affected_url or f.affected_host }}` |
{% endfor %}
{% else %}
No findings were identified during this assessment.
{% endif %}

## 4. Detailed Findings

{% for f in findings %}
### 4.{{ loop.index }}. {{ f.title }}

| Field | Value |
|-------|-------|
| **Severity** | {{ f.severity.value | upper }} |
| **Confidence** | {{ f.confidence }} |
| **Category** | {{ f.category }} |
| **CVSS Score** | {{ f.cvss_score or "N/A" }} |
| **CVE** | {{ f.cve_ids | join(", ") if f.cve_ids else "N/A" }} |
| **Tool** | {{ f.tool_source }} |

**Description:**
{{ f.description }}

**Affected Resource:**
`{{ f.affected_url or f.affected_host }}`{% if f.affected_port %} (port {{ f.affected_port }}){% endif %}

{% if f.evidence %}
**Evidence:**
```
{{ f.evidence[:3000] }}
```
{% endif %}

{% if f.description and '**Impact:**' in f.description %}
{% set parts = f.description.split('**Impact:**') %}
**Impact:**
{{ parts[1].strip() }}
{% endif %}

{% if f.remediation %}
**Remediation:**
{{ f.remediation }}
{% endif %}

{% if f.references %}
**References:**
{% for ref in f.references %}- {{ ref }}
{% endfor %}
{% endif %}

---

{% endfor %}

## 5. Exploitation Results

{% if exploit_results %}
| Finding | Tool | Success | Access Gained |
|---------|------|---------|---------------|
{% for e in exploit_results %}| {{ e.finding_id[:8] }} | {{ e.tool_used }} | {{ "✅ Yes" if e.success else "❌ No" }} | {{ e.access_gained or "N/A" }} |
{% endfor %}
{% else %}
No exploitation was attempted during this assessment.
{% endif %}

## 6. Recommendations

### Immediate Actions (Critical/High)
{% for f in findings if f.severity.value in ["critical", "high"] %}
1. **{{ f.title }}**: {{ f.remediation or "Investigate and remediate immediately." }}
{% endfor %}
{% if not findings %}
No immediate actions required.
{% endif %}

### Short-term Actions (Medium)
{% for f in findings if f.severity.value == "medium" %}
1. **{{ f.title }}**: {{ f.remediation or "Review and address within the current sprint." }}
{% endfor %}

### Long-term Actions (Low/Info)
{% for f in findings if f.severity.value in ["low", "info"] %}
1. **{{ f.title }}**: {{ f.remediation or "Consider implementing as part of security hardening." }}
{% endfor %}

## 7. AI Risk Assessment Summary

{% if findings %}
| Metric | Value |
|--------|-------|
| **Total Findings** | {{ findings | length }} |
| **Critical** | {{ findings | selectattr('severity', 'equalto', severity_critical) | list | length }} |
| **High** | {{ findings | selectattr('severity', 'equalto', severity_high) | list | length }} |
{% if avg_cvss > 0 %}| **Average CVSS** | {{ '%.1f' | format(avg_cvss) }} / 10.0 |{% endif %}

{% if findings | selectattr('severity', 'equalto', severity_critical) | list | length > 0 %}
> ⚠️ **CRITICAL vulnerabilities detected.** Immediate remediation is required before production deployment.
{% endif %}
{% else %}
No findings to assess.
{% endif %}

## 8. Tool Execution Log

| Tool | Phase | Status | Duration |
|------|-------|--------|----------|
{% for e in session.tool_executions[:30] %}| {{ e.tool_name }} | {{ e.phase.value }} | {{ e.status }} | {{ "%.1f" | format(e.duration_seconds) }}s |
{% endfor %}

---

*Report generated by Security Agent v1.0.0 on {{ report_date }}*
"""


class ReportGenerator:
    """Generate penetration test reports from scan sessions."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, session: ScanSession) -> str:
        """Generate a markdown report for the given session."""
        from jinja2 import Template

        template = Template(REPORT_TEMPLATE)
        targets = ", ".join(t.value for t in session.targets)
        tools_used = sorted({e.tool_name for e in session.tool_executions})

        # Calculate duration
        if session.completed_at and session.started_at:
            delta = session.completed_at - session.started_at
            duration = f"{delta.total_seconds():.0f} seconds"
        else:
            duration = "In progress"

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            session.findings,
            key=lambda f: severity_order.get(f.severity.value, 5),
        )

        # Calculate average CVSS
        cvss_scores = [f.cvss_score for f in session.findings if f.cvss_score]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        report = template.render(
            session=session,
            targets=targets,
            tools_used=tools_used,
            total_findings=len(session.findings),
            severity_summary=session.severity_summary,
            findings=sorted_findings,
            exploit_results=session.exploit_results,
            duration=duration,
            report_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            avg_cvss=avg_cvss,
            severity_critical=Severity.CRITICAL,
            severity_high=Severity.HIGH,
        )

        # Save report
        filename = f"report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = Path(self.output_dir) / filename
        report_path.write_text(report)

        logger.info(f"Report saved to: {report_path}")
        return str(report_path)

    def generate_json(self, session: ScanSession) -> str:
        """Generate a JSON report for the given session."""
        data = {
            "session_id": session.id,
            "status": session.status,
            "started_at": session.started_at.isoformat(),
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "targets": [t.model_dump(mode="json") for t in session.targets],
            "findings": [f.model_dump(mode="json") for f in session.findings],
            "exploit_results": [e.model_dump(mode="json") for e in session.exploit_results],
            "severity_summary": session.severity_summary,
            "tools_executed": len(session.tool_executions),
        }

        filename = f"report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = Path(self.output_dir) / filename
        report_path.write_text(json.dumps(data, indent=2, default=str))

        logger.info(f"JSON report saved to: {report_path}")
        return str(report_path)
