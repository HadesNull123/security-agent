"""
PDF Report Generator - Converts Markdown reports to professional PDF documents.
Uses reportlab for PDF generation.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_pdf_report(
    session: Any,
    output_dir: str = "./reports",
) -> str:
    """
    Generate a PDF penetration test report.

    Uses reportlab for PDF creation. Falls back to a basic text PDF
    if complex formatting isn't available.

    Args:
        session: ScanSession with findings and results
        output_dir: Output directory

    Returns:
        Path to generated PDF file
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch, mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
            HRFlowable,
        )
    except ImportError:
        logger.warning("reportlab not installed. Install with: pip install reportlab")
        return _fallback_text_pdf(session, output_dir)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = Path(output_dir) / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=25 * mm,
    )

    # ── Styles ──
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "CustomTitle", parent=styles["Title"], fontSize=24,
        textColor=colors.HexColor("#1a1a2e"), spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading1"], fontSize=16,
        textColor=colors.HexColor("#16213e"), spaceBefore=20, spaceAfter=10,
        borderWidth=1, borderColor=colors.HexColor("#0f3460"),
        borderPadding=5,
    ))
    styles.add(ParagraphStyle(
        "SubHeader", parent=styles["Heading2"], fontSize=13,
        textColor=colors.HexColor("#0f3460"), spaceBefore=12, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "BodyText_Custom", parent=styles["BodyText"], fontSize=10,
        leading=14, alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        "Code", parent=styles["Code"], fontSize=8,
        backColor=colors.HexColor("#f0f0f0"), leftIndent=10,
        rightIndent=10, spaceBefore=5, spaceAfter=5,
    ))

    # ── Build content ──
    story = []

    # Cover page
    story.append(Spacer(1, 80))
    story.append(Paragraph("🛡️ Penetration Testing Report", styles["CustomTitle"]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="80%", thickness=2, color=colors.HexColor("#0f3460")))
    story.append(Spacer(1, 20))

    targets = ", ".join(t.value for t in session.targets)
    cover_data = [
        ["Report Date", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Session ID", session.id[:8]],
        ["Targets", targets],
        ["Status", session.status.upper()],
        ["Total Findings", str(len(session.findings))],
    ]
    cover_table = Table(cover_data, colWidths=[150, 300])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8e8e8")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWHEIGHT", (0, 0), (-1, -1), 25),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    severity_text = ", ".join(
        f"{s.upper()}: {c}" for s, c in session.severity_summary.items()
    )
    story.append(Paragraph(
        f"A security assessment was conducted against <b>{targets}</b>. "
        f"The assessment identified <b>{len(session.findings)}</b> security findings: "
        f"{severity_text or 'None'}.",
        styles["BodyText_Custom"],
    ))
    story.append(Spacer(1, 10))

    # Severity summary table
    if session.severity_summary:
        sev_colors = {
            "critical": colors.HexColor("#dc2626"),
            "high": colors.HexColor("#ea580c"),
            "medium": colors.HexColor("#ca8a04"),
            "low": colors.HexColor("#2563eb"),
            "info": colors.HexColor("#6b7280"),
        }
        sev_data = [["Severity", "Count"]]
        sev_row_colors = []
        for sev, count in session.severity_summary.items():
            sev_data.append([sev.upper(), str(count)])
            sev_row_colors.append(sev_colors.get(sev, colors.grey))

        sev_table = Table(sev_data, colWidths=[200, 100])
        sev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWHEIGHT", (0, 0), (-1, -1), 22),
        ]
        for i, color in enumerate(sev_row_colors):
            sev_style.append(("TEXTCOLOR", (0, i + 1), (0, i + 1), color))
            sev_style.append(("FONTNAME", (0, i + 1), (0, i + 1), "Helvetica-Bold"))

        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)

    story.append(Spacer(1, 15))

    # Findings Summary
    story.append(Paragraph("2. Findings Summary", styles["SectionHeader"]))

    if session.findings:
        findings_data = [["#", "Title", "Severity", "Affected"]]
        for i, f in enumerate(session.findings, 1):
            findings_data.append([
                str(i),
                f.title[:50],
                f.severity.value.upper(),
                (f.affected_url or f.affected_host)[:40],
            ])

        findings_table = Table(findings_data, colWidths=[30, 200, 70, 200])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWHEIGHT", (0, 0), (-1, -1), 20),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        story.append(findings_table)
    else:
        story.append(Paragraph(
            "No findings were identified during this assessment.",
            styles["BodyText_Custom"],
        ))

    story.append(Spacer(1, 15))

    # Detailed Findings
    story.append(Paragraph("3. Detailed Findings", styles["SectionHeader"]))

    for i, f in enumerate(session.findings, 1):
        story.append(Paragraph(f"3.{i}. {f.title}", styles["SubHeader"]))

        detail_data = [
            ["Severity", f.severity.value.upper()],
            ["Confidence", f.confidence],
            ["Category", f.category or "N/A"],
            ["CVSS", str(f.cvss_score) if f.cvss_score else "N/A"],
            ["CVE", ", ".join(f.cve_ids) if f.cve_ids else "N/A"],
            ["Tool", f.tool_source],
            ["Affected", (f.affected_url or f.affected_host)[:80]],
        ]
        detail_table = Table(detail_data, colWidths=[100, 380])
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8e8e8")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(detail_table)
        story.append(Spacer(1, 5))

        if f.description:
            story.append(Paragraph(f"<b>Description:</b> {_escape_html(f.description[:500])}", styles["BodyText_Custom"]))
        if f.evidence:
            story.append(Paragraph(f"<b>Evidence:</b>", styles["BodyText_Custom"]))
            story.append(Paragraph(_escape_html(f.evidence[:800]), styles["Code"]))
        if f.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {_escape_html(f.remediation[:500])}", styles["BodyText_Custom"]))

        story.append(Spacer(1, 10))

    # Tool execution log
    story.append(PageBreak())
    story.append(Paragraph("4. Tool Execution Log", styles["SectionHeader"]))

    if session.tool_executions:
        log_data = [["Tool", "Phase", "Status", "Duration"]]
        for e in session.tool_executions[:40]:
            log_data.append([
                e.tool_name,
                e.phase.value,
                e.status,
                f"{e.duration_seconds:.1f}s",
            ])
        log_table = Table(log_data, colWidths=[120, 100, 100, 80])
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWHEIGHT", (0, 0), (-1, -1), 18),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        story.append(log_table)

    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Paragraph(
        f"<i>Generated by Security Agent v1.0.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</i>",
        styles["BodyText_Custom"],
    ))

    # Build PDF
    doc.build(story)
    logger.info(f"PDF report saved to: {filepath}")
    return str(filepath)


def _escape_html(text: str) -> str:
    """Escape HTML special characters for reportlab Paragraph."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fallback_text_pdf(session: Any, output_dir: str) -> str:
    """Fallback: generate a simple text file when reportlab is not available."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = Path(output_dir) / filename

    lines = [
        "=" * 60,
        "PENETRATION TESTING REPORT",
        "=" * 60,
        f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"Session: {session.id[:8]}",
        f"Targets: {', '.join(t.value for t in session.targets)}",
        f"Findings: {len(session.findings)}",
        "",
    ]

    for i, f in enumerate(session.findings, 1):
        lines.append(f"\n--- Finding #{i} ---")
        lines.append(f"Title: {f.title}")
        lines.append(f"Severity: {f.severity.value.upper()}")
        lines.append(f"Affected: {f.affected_url or f.affected_host}")
        lines.append(f"Description: {f.description[:300]}")
        if f.remediation:
            lines.append(f"Remediation: {f.remediation[:300]}")

    filepath.write_text("\n".join(lines))
    logger.warning(f"reportlab not available, saved text report to: {filepath}")
    return str(filepath)
