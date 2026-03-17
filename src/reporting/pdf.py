"""
PDF Report Generator — Professional penetration testing report.

Features:
- Cover page with branding, target info, scan summary
- Executive Summary with risk gauge
- Severity distribution chart (bar)
- Table of Contents
- Detailed findings: description, impact analysis, evidence, remediation steps
- Remediation Priority Roadmap (Immediate / Short-Term / Long-Term)
- Tool Execution Log
- Footer with page numbers
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ─── Color Palette ───────────────────────────────────────────

DARK_NAVY    = "#0d1b2a"
NAVY         = "#1b263b"
BLUE         = "#1e4d8c"
ACCENT_BLUE  = "#4a90d9"
RED          = "#c0392b"
ORANGE       = "#e67e22"
YELLOW       = "#f39c12"
LIGHT_BLUE   = "#2980b9"
GREEN        = "#27ae60"
GRAY         = "#7f8c8d"
LIGHT_GRAY   = "#ecf0f1"
WHITE        = "#ffffff"
BLACK        = "#1a1a1a"

SEV_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f39c12",
    "low":      "#2980b9",
    "info":     "#7f8c8d",
}

SEV_BG = {
    "critical": "#fdecea",
    "high":     "#fef3e2",
    "medium":   "#fefbed",
    "low":      "#e8f4fd",
    "info":     "#f4f6f7",
}


def _h(hex_color: str):
    """Convert hex string to reportlab HexColor."""
    from reportlab.lib import colors
    return colors.HexColor(hex_color)


def _safe(text: str, max_len: int = 5000) -> str:
    """Escape HTML for reportlab Paragraph and truncate."""
    if not text:
        return ""
    text = str(text)[:max_len]
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("\n", "<br/>")
    )


def _numbered_list(items: list[str], style) -> list:
    """Return a list of Paragraph elements for a numbered list."""
    from reportlab.platypus import Paragraph
    result = []
    for i, item in enumerate(items, 1):
        result.append(Paragraph(f"&nbsp;&nbsp;<b>{i}.</b> {_safe(item)}", style))
    return result


class _NumberedCanvas:
    """Canvas with page numbers."""
    pass


def _build_styles():
    """Build all paragraph styles."""
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()

    def s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_title": s("cover_title", "Normal",
            fontSize=32, textColor=_h(WHITE), fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=8, leading=38),
        "cover_sub": s("cover_sub", "Normal",
            fontSize=13, textColor=_h(ACCENT_BLUE), fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=4),
        "cover_label": s("cover_label", "Normal",
            fontSize=10, textColor=_h(LIGHT_GRAY), fontName="Helvetica",
            alignment=TA_LEFT),
        "cover_value": s("cover_value", "Normal",
            fontSize=10, textColor=_h(WHITE), fontName="Helvetica-Bold",
            alignment=TA_LEFT),

        "section": s("section", "Normal",
            fontSize=16, textColor=_h(NAVY), fontName="Helvetica-Bold",
            spaceBefore=24, spaceAfter=10, leading=20,
            borderWidth=0, leftIndent=0),
        "subsection": s("subsection", "Normal",
            fontSize=12, textColor=_h(BLUE), fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6),
        "body": s("body", "Normal",
            fontSize=10, textColor=_h(BLACK), leading=15,
            alignment=TA_JUSTIFY, spaceAfter=6),
        "body_left": s("body_left", "Normal",
            fontSize=10, textColor=_h(BLACK), leading=15),
        "small": s("small", "Normal",
            fontSize=8, textColor=_h(GRAY), leading=12),
        "code": s("code", "Normal",
            fontSize=8, fontName="Courier", textColor=_h(BLACK),
            backColor=_h("#f8f9fa"), leftIndent=10, rightIndent=10,
            spaceBefore=4, spaceAfter=4, leading=12,
            borderWidth=1, borderColor=_h("#dee2e6"), borderPadding=6),
        "label_key": s("label_key", "Normal",
            fontSize=9, fontName="Helvetica-Bold", textColor=_h(NAVY)),
        "label_val": s("label_val", "Normal",
            fontSize=9, textColor=_h(BLACK)),
        "toc_entry": s("toc_entry", "Normal",
            fontSize=10, textColor=_h(BLUE), leading=16),
        "finding_title": s("finding_title", "Normal",
            fontSize=13, fontName="Helvetica-Bold", textColor=_h(WHITE),
            leading=16),
        "remediation": s("remediation", "Normal",
            fontSize=10, textColor=_h(BLACK), leading=14,
            backColor=_h("#f0faf4"), leftIndent=8, rightIndent=8,
            borderWidth=1, borderColor=_h(GREEN), borderPadding=6),
        "impact": s("impact", "Normal",
            fontSize=10, textColor=_h(BLACK), leading=14,
            backColor=_h("#fff8e1"), leftIndent=8, rightIndent=8,
            borderWidth=1, borderColor=_h(YELLOW), borderPadding=6),
        "footer": s("footer", "Normal",
            fontSize=8, textColor=_h(GRAY), alignment=TA_CENTER),
    }


def _severity_badge(severity: str, styles) -> "Paragraph":
    """Return a severity badge paragraph."""
    from reportlab.platypus import Paragraph
    sev = severity.lower()
    color = SEV_COLORS.get(sev, GRAY)
    label = sev.upper()
    return Paragraph(
        f'<font color="{color}"><b>● {label}</b></font>',
        styles["body_left"],
    )


def _page_header_footer(canvas, doc):
    """Draw header and footer on each page."""
    from reportlab.lib.units import mm
    canvas.saveState()
    w, h = doc.pagesize

    # Header bar (only on non-cover pages)
    if doc.page > 1:
        canvas.setFillColor(_h(DARK_NAVY))
        canvas.rect(0, h - 18*mm, w, 18*mm, fill=True, stroke=False)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(_h(WHITE))
        canvas.drawString(20*mm, h - 12*mm, "🛡️  SECURITY ASSESSMENT REPORT  |  CONFIDENTIAL")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_h(ACCENT_BLUE))
        canvas.drawRightString(w - 20*mm, h - 12*mm, datetime.utcnow().strftime("%Y-%m-%d"))

    # Footer
    canvas.setFillColor(_h(LIGHT_GRAY))
    canvas.rect(0, 0, w, 12*mm, fill=True, stroke=False)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(_h(GRAY))
    canvas.drawCentredString(w / 2, 4*mm, f"Page {doc.page}  •  Generated by Security Agent  •  CONFIDENTIAL")
    canvas.restoreState()


def _draw_cover(story, session, targets, styles, pagesize):
    """Build the cover page."""
    from reportlab.lib.units import mm
    from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, HRFlowable, PageBreak
    W, H = pagesize

    # Dark background — we fake it with a full-width colored table
    cover_bg = Table(
        [[""]],
        colWidths=[W - 40*mm],
        rowHeights=[H * 0.45],
    )
    cover_bg.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _h(DARK_NAVY)),
        ("TOPPADDING", (0, 0), (-1, -1), 30),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
    ]))

    story.append(Spacer(1, 40))
    story.append(Paragraph("🛡️  SECURITY ASSESSMENT REPORT", styles["cover_title"]))
    story.append(Paragraph("AI-Powered Penetration Testing", styles["cover_sub"]))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="60%", thickness=2, color=_h(ACCENT_BLUE), spaceAfter=20))

    # Cover info table — build comprehensive datetime info
    from datetime import timezone, timedelta
    tz_vn = timezone(timedelta(hours=7))  # Vietnam UTC+7
    now_utc = datetime.utcnow()
    now_vn  = datetime.now(tz_vn)

    # Try to get scan start/end times from session
    scan_start = getattr(session, "started_at", None)
    scan_end   = getattr(session, "completed_at", None)

    if isinstance(scan_start, datetime):
        start_str = scan_start.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        start_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    if isinstance(scan_end, datetime) and isinstance(scan_start, datetime):
        duration = scan_end - scan_start
        total_sec = int(duration.total_seconds())
        duration_str = f"{total_sec // 3600}h {(total_sec % 3600) // 60}m {total_sec % 60}s"
        end_str = scan_end.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        end_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        duration_str = "N/A"

    sev = session.severity_summary
    critical_n = sev.get("critical", 0)
    high_n     = sev.get("high", 0)
    medium_n   = sev.get("medium", 0)
    low_n      = sev.get("low", 0)

    overall_risk = "CRITICAL" if critical_n > 0 else \
                   "HIGH" if high_n > 0 else \
                   "MEDIUM" if medium_n > 0 else \
                   "LOW" if low_n > 0 else "INFORMATIONAL"
    risk_color = SEV_COLORS.get(overall_risk.lower(), GRAY)

    cover_data = [
        ["Target(s)",          targets],
        ["Report Date (UTC)",  now_utc.strftime("%A, %B %d, %Y")],
        ["Report Time (UTC)",  now_utc.strftime("%H:%M:%S UTC")],
        ["Report Time (VN)",   now_vn.strftime("%H:%M:%S UTC+7 (Vietnam)")],
        ["Scan Started",       start_str],
        ["Scan Ended",         end_str],
        ["Scan Duration",      duration_str],
        ["Session ID",         session.id[:16] if len(session.id) >= 16 else session.id],
        ["Scan Mode",          getattr(session, "scan_mode", "N/A").upper()],
        ["Total Findings",     str(len(session.findings))],
        ["Overall Risk",       f'<font color="{risk_color}"><b>{overall_risk}</b></font>'],
    ]

    tbl = Table(cover_data, colWidths=[140, 260])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _h(NAVY)),
        ("BACKGROUND", (1, 0), (1, -1), _h("#1e2d40")),
        ("TEXTCOLOR", (0, 0), (0, -1), _h(ACCENT_BLUE)),
        ("TEXTCOLOR", (1, 0), (1, -1), _h(WHITE)),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, _h("#2c3e50")),
        ("ROWHEIGHT", (0, 0), (-1, -1), 24),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        # Highlight datetime rows
        ("BACKGROUND", (0, 1), (-1, 3), _h("#15202e")),
        # Highlight risk row
        ("BACKGROUND", (0, -1), (-1, -1), _h("#1a0a0a")),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 30))

    # Severity summary on cover
    if any(sev.values()):
        sev_cover = [["Severity", "Count", "Risk Level"]]
        sev_rows = [
            ("critical", "CVSS 9.0–10.0"),
            ("high",     "CVSS 7.0–8.9"),
            ("medium",   "CVSS 4.0–6.9"),
            ("low",      "CVSS 1.0–3.9"),
            ("info",     "Informational"),
        ]
        for s_key, cvss in sev_rows:
            count = sev.get(s_key, 0)
            if count > 0:
                sev_cover.append([s_key.upper(), str(count), cvss])
        if len(sev_cover) > 1:
            sev_tbl = Table(sev_cover, colWidths=[100, 80, 220])
            sev_style = [
                ("BACKGROUND", (0, 0), (-1, 0), _h(BLUE)),
                ("TEXTCOLOR", (0, 0), (-1, 0), _h(WHITE)),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, _h(GRAY)),
                ("ROWHEIGHT", (0, 0), (-1, -1), 22),
            ]
            for row_idx, (s_key, _) in enumerate(sev_rows, 1):
                if sev.get(s_key, 0) > 0:
                    sev_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), _h(SEV_COLORS.get(s_key, GRAY))))
                    sev_style.append(("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"))
            sev_tbl.setStyle(TableStyle(sev_style))
            story.append(sev_tbl)

    story.append(Spacer(1, 40))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(NAVY)))
    story.append(Paragraph(
        "<i>This report is confidential and intended solely for authorized recipients.</i>",
        styles["small"],
    ))
    story.append(PageBreak())


def _draw_finding(i: int, f: Any, styles, story):
    """Add a detailed finding section."""
    from reportlab.platypus import (
        Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    )

    sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
    sev_color = _h(SEV_COLORS.get(sev, GRAY))
    sev_bg    = _h(SEV_BG.get(sev, LIGHT_GRAY))

    # ─ Finding header bar ─
    header_tbl = Table(
        [[f"FINDING #{i:02d}", f"  {f.title}", sev.upper()]],
        colWidths=[70, 330, 80],
    )
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _h(NAVY)),
        ("BACKGROUND", (2, 0), (2, 0), sev_color),
        ("TEXTCOLOR", (0, 0), (1, 0), _h(WHITE)),
        ("TEXTCOLOR", (2, 0), (2, 0), _h(WHITE)),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "LEFT"),
        ("ALIGN", (2, 0), (2, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT", (0, 0), (-1, -1), 28),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(header_tbl)

    # ─ Metadata table ─
    meta_rows = [
        ["Severity",   sev.upper()],
        ["Confidence", getattr(f, "confidence", "medium").upper()],
        ["Category",   getattr(f, "category", "N/A") or "N/A"],
        ["Affected",   str(getattr(f, "affected_url", "") or getattr(f, "affected_host", "") or "N/A")[:120]],
    ]
    if getattr(f, "cvss_score", None):
        meta_rows.append(["CVSS Score", f"{f.cvss_score:.1f} / 10.0"])
    if getattr(f, "cve_ids", None):
        meta_rows.append(["CVE IDs", ", ".join(f.cve_ids[:5])])
    if getattr(f, "tool_source", ""):
        meta_rows.append(["Discovered by", f.tool_source])
    if getattr(f, "references", None):
        refs = [str(r) for r in f.references[:3]]
        meta_rows.append(["References", "\n".join(refs)])

    meta_tbl = Table(meta_rows, colWidths=[100, 380])
    meta_style = [
        ("BACKGROUND", (0, 0), (0, -1), sev_bg),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    # Color severity value cell
    meta_style.append(("TEXTCOLOR", (1, 0), (1, 0), sev_color))
    meta_style.append(("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"))
    meta_tbl.setStyle(TableStyle(meta_style))
    story.append(meta_tbl)
    story.append(Spacer(1, 6))

    # ─ Description ─
    desc = str(getattr(f, "description", "") or "")
    if desc:
        # Split out embedded Impact section if present
        impact = ""
        if "**Impact:**" in desc:
            parts = desc.split("**Impact:**", 1)
            desc = parts[0].strip()
            impact = parts[1].strip()
        elif "Impact:" in desc:
            parts = desc.split("Impact:", 1)
            desc = parts[0].strip()
            impact = parts[1].strip()

        story.append(Paragraph("<b>📋 Description</b>", styles["subsection"]))
        story.append(Paragraph(_safe(desc, 3000), styles["body"]))

        if impact:
            story.append(Paragraph(
                f"<b>⚠ Impact:</b> {_safe(impact, 1000)}",
                styles["impact"],
            ))
            story.append(Spacer(1, 4))

    # ─ Evidence ─
    evidence = str(getattr(f, "evidence", "") or "")
    if evidence:
        story.append(Paragraph("<b>🔍 Evidence / Proof of Concept</b>", styles["subsection"]))
        # Split by lines — show as code block
        story.append(Paragraph(_safe(evidence, 2000), styles["code"]))
        story.append(Spacer(1, 4))

    # ─ Remediation ─
    remediation = str(getattr(f, "remediation", "") or "")
    if remediation:
        story.append(Paragraph("<b>🔧 Remediation</b>", styles["subsection"]))
        # Split numbered steps if present
        lines = remediation.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            story.append(Paragraph(
                f"&nbsp;&nbsp;{_safe(line, 500)}",
                styles["remediation"],
            ))
        story.append(Spacer(1, 4))

    story.append(HRFlowable(width="100%", thickness=0.5, color=_h(LIGHT_GRAY), spaceAfter=12))


def generate_pdf_report(session: Any, output_dir: str = "./reports") -> str:
    """
    Generate a professional penetration testing PDF report.

    Args:
        session: ScanSession with findings and results
        output_dir: Directory to save the PDF

    Returns:
        Path to the generated PDF file
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable, KeepTogether,
        )
    except ImportError:
        logger.warning("reportlab not installed. Install with: pip install reportlab")
        return _fallback_text_pdf(session, output_dir)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"security_report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = Path(output_dir) / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title="Security Assessment Report",
        author="Security Agent",
        subject="Penetration Testing Report",
    )

    styles = _build_styles()
    story  = []
    W, H   = A4

    targets = ", ".join(t.value for t in session.targets) if hasattr(session, "targets") else "N/A"

    # ═══════════════════════════════════════════════════════
    # 1. Cover Page
    # ═══════════════════════════════════════════════════════
    _draw_cover(story, session, targets, styles, A4)

    # ═══════════════════════════════════════════════════════
    # 2. Table of Contents
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("Table of Contents", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))
    toc_items = [
        ("1.", "Executive Summary"),
        ("2.", "Findings Summary"),
        ("3.", f"Detailed Findings ({len(session.findings)})"),
        ("4.", "Remediation Roadmap"),
        ("5.", "Tool Execution Log"),
        ("6.", "Appendix"),
    ]
    for num, title in toc_items:
        story.append(Paragraph(
            f'<b>{num}</b>&nbsp;&nbsp;{title}',
            styles["toc_entry"],
        ))
    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 3. Executive Summary
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))

    sev = session.severity_summary
    critical_n = sev.get("critical", 0)
    high_n     = sev.get("high", 0)
    medium_n   = sev.get("medium", 0)
    low_n      = sev.get("low", 0)
    info_n     = sev.get("info", 0)
    total_n    = len(session.findings)

    # Risk rating
    overall_risk = (
        "CRITICAL" if critical_n > 0 else
        "HIGH"     if high_n > 0 else
        "MEDIUM"   if medium_n > 0 else
        "LOW"      if low_n > 0 else
        "INFORMATIONAL"
    )
    risk_color = SEV_COLORS.get(overall_risk.lower(), GRAY)

    story.append(Paragraph(
        f"A comprehensive security assessment was conducted against <b>{_safe(targets)}</b>. "
        f"The assessment identified <b>{total_n}</b> security findings across all severity levels. "
        f"The overall risk rating is "
        f'<font color="{risk_color}"><b>{overall_risk}</b></font>.',
        styles["body"],
    ))
    story.append(Spacer(1, 10))

    # Severity bar chart (text-based using table widths as bars)
    max_count = max(critical_n, high_n, medium_n, low_n, info_n, 1)
    BAR_MAX = 200  # max bar width in points

    chart_data = [["Severity", "Count", "Distribution"]]
    chart_rows = [
        ("CRITICAL", critical_n, SEV_COLORS["critical"]),
        ("HIGH",     high_n,     SEV_COLORS["high"]),
        ("MEDIUM",   medium_n,   SEV_COLORS["medium"]),
        ("LOW",      low_n,      SEV_COLORS["low"]),
        ("INFO",     info_n,     SEV_COLORS["info"]),
    ]

    for label, count, color in chart_rows:
        bar_w = int(BAR_MAX * count / max_count) if count else 0
        chart_data.append([label, str(count), ""])

    chart_tbl = Table(chart_data, colWidths=[80, 50, BAR_MAX + 20])
    chart_style = [
        ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), _h(WHITE)),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
        ("ROWHEIGHT", (0, 0), (-1, -1), 22),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, (_, _, color) in enumerate(chart_rows, 1):
        chart_style.append(("TEXTCOLOR", (0, i), (0, i), _h(color)))
        chart_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    chart_tbl.setStyle(TableStyle(chart_style))
    story.append(chart_tbl)
    story.append(Spacer(1, 12))

    # CVSS stats
    cvss_scores = [f.cvss_score for f in session.findings if getattr(f, "cvss_score", None)]
    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        max_cvss = max(cvss_scores)
        story.append(Paragraph(
            f"<b>CVSS Statistics:</b> Average score <b>{avg_cvss:.1f}</b>, "
            f"Maximum score <b>{max_cvss:.1f}</b> / 10.0",
            styles["body"],
        ))

    # Key findings highlight
    critical_findings = [f for f in session.findings if getattr(f.severity, "value", "") == "critical"]
    if critical_findings:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f'<font color="{SEV_COLORS["critical"]}"><b>⚠ Critical Findings Requiring Immediate Attention:</b></font>',
            styles["body"],
        ))
        for cf in critical_findings[:5]:
            story.append(Paragraph(
                f"&nbsp;&nbsp;• <b>{_safe(cf.title)}</b> — {_safe(str(getattr(cf, 'affected_url', '') or getattr(cf, 'affected_host', ''))[:80])}",
                styles["body_left"],
            ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 4. Findings Summary Table
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("2. Findings Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))

    if session.findings:
        hdr = [["#", "Title", "Severity", "Category", "Affected"]]
        rows = []
        for idx, f in enumerate(session.findings, 1):
            sev_val = getattr(f.severity, "value", str(f.severity)).lower()
            rows.append([
                str(idx),
                str(f.title)[:60],
                sev_val.upper(),
                str(getattr(f, "category", "") or "—")[:20],
                str(getattr(f, "affected_url", "") or getattr(f, "affected_host", "") or "—")[:45],
            ])

        tbl = Table(hdr + rows, colWidths=[22, 170, 60, 80, 148])
        tbl_style = [
            ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _h(WHITE)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
            ("ROWHEIGHT", (0, 0), (-1, -1), 20),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]
        for row_i, f in enumerate(session.findings, 1):
            sev_val = getattr(f.severity, "value", str(f.severity)).lower()
            color = SEV_COLORS.get(sev_val, GRAY)
            bg = SEV_BG.get(sev_val, WHITE)
            tbl_style.append(("BACKGROUND", (0, row_i), (-1, row_i),
                               _h(bg) if row_i % 2 == 0 else _h(WHITE)))
            tbl_style.append(("TEXTCOLOR", (2, row_i), (2, row_i), _h(color)))
            tbl_style.append(("FONTNAME", (2, row_i), (2, row_i), "Helvetica-Bold"))

        tbl.setStyle(TableStyle(tbl_style))
        story.append(tbl)
    else:
        story.append(Paragraph("No security findings were identified.", styles["body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 5. Detailed Findings
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("3. Detailed Findings", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))

    for i, f in enumerate(session.findings, 1):
        _draw_finding(i, f, styles, story)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 6. Remediation Roadmap
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("4. Remediation Roadmap", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))

    def _findings_by_sev(sevs):
        return [f for f in session.findings
                if getattr(f.severity, "value", str(f.severity)).lower() in sevs]

    roadmap_sections = [
        ("🚨 Immediate Action (0–7 days)",  ["critical"],         RED,    "Address all critical vulnerabilities immediately. These represent severe risks that may be actively exploitable."),
        ("⚡ Short-Term (1–4 weeks)",        ["high"],             ORANGE, "High severity findings should be remediated in the next sprint or iteration."),
        ("📅 Mid-Term (1–3 months)",         ["medium"],           YELLOW, "Medium severity findings require attention in the near term to prevent escalation."),
        ("📋 Long-Term (3–6 months)",        ["low", "info"],      BLUE,   "Low severity and informational findings should be tracked and addressed in regular hardening cycles."),
    ]

    for title, sevs, color, guidance in roadmap_sections:
        matching = _findings_by_sev(sevs)
        if not matching:
            continue
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f'<font color="{color}"><b>{title}</b></font>',
            styles["subsection"],
        ))
        story.append(Paragraph(guidance, styles["body"]))
        for f in matching:
            story.append(Paragraph(
                f"&nbsp;&nbsp;• <b>{_safe(f.title)}</b>",
                styles["body_left"],
            ))
            rem = str(getattr(f, "remediation", "") or "")
            if rem:
                # First sentence of remediation
                first_line = rem.split("\n")[0].strip()[:200]
                story.append(Paragraph(
                    f"&nbsp;&nbsp;&nbsp;&nbsp;<i>{_safe(first_line)}</i>",
                    styles["small"],
                ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 7. Tool Execution Log
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("5. Tool Execution Log", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))

    if getattr(session, "tool_executions", None):
        log_hdr = [["Tool", "Phase", "Status", "Duration", "Findings"]]
        log_rows = []
        for e in session.tool_executions[:60]:
            findings_count = str(getattr(e, "findings_count", "—"))
            log_rows.append([
                e.tool_name,
                e.phase.value if hasattr(e.phase, "value") else str(e.phase),
                e.status.upper(),
                f"{e.duration_seconds:.1f}s",
                findings_count,
            ])
        log_tbl = Table(log_hdr + log_rows, colWidths=[100, 80, 70, 70, 60])
        log_style = [
            ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _h(WHITE)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
            ("ROWHEIGHT", (0, 0), (-1, -1), 18),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_h(WHITE), _h(LIGHT_GRAY)]),
        ]
        for row_i, e in enumerate(session.tool_executions[:60], 1):
            st = getattr(e, "status", "").lower()
            if st in ("failed", "error"):
                log_style.append(("TEXTCOLOR", (2, row_i), (2, row_i), _h(RED)))
            elif st == "completed":
                log_style.append(("TEXTCOLOR", (2, row_i), (2, row_i), _h(GREEN)))
        log_tbl.setStyle(TableStyle(log_style))
        story.append(log_tbl)
    else:
        story.append(Paragraph("No tool execution data available.", styles["body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 8. Appendix / Methodology
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("6. Appendix — Methodology", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=10))
    story.append(Paragraph(
        "The security assessment followed a structured penetration testing methodology "
        "aligned with industry standards (OWASP, PTES, NIST SP 800-115). "
        "The engagement was conducted in the following phases:",
        styles["body"],
    ))
    phases = [
        ("Reconnaissance", "Passive and active information gathering: subdomain enumeration, DNS, port scanning, technology fingerprinting, WAF detection."),
        ("Vulnerability Scanning", "Automated vulnerability detection using nuclei (CVE templates), Nikto, TestSSL, secret scanning, email security checks, and WAF bypass testing."),
        ("Exploitation", "Controlled exploitation of identified vulnerabilities to determine impact and confirm findings."),
        ("Reporting", "AI-powered analysis, severity classification, risk assessment, and remediation guidance generation."),
    ]
    for phase_name, desc in phases:
        story.append(Paragraph(f"<b>{phase_name}:</b> {_safe(desc)}", styles["body"]))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(LIGHT_GRAY)))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<i>Report generated by Security Agent v1.0.0 on "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. "
        f"This document is confidential.</i>",
        styles["footer"],
    ))

    # ═══════════════════════════════════════════════════════
    # Build PDF
    # ═══════════════════════════════════════════════════════
    doc.build(
        story,
        onFirstPage=_page_header_footer,
        onLaterPages=_page_header_footer,
    )
    logger.info(f"✅ PDF report saved: {filepath}")
    return str(filepath)


def _fallback_text_pdf(session: Any, output_dir: str) -> str:
    """Fallback plain-text report when reportlab is unavailable."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"report_{session.id[:8]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = Path(output_dir) / filename

    lines = [
        "=" * 70,
        "  SECURITY ASSESSMENT REPORT",
        "=" * 70,
        f"  Date    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Session : {session.id[:12]}",
        f"  Targets : {', '.join(t.value for t in session.targets)}",
        f"  Findings: {len(session.findings)}",
        "=" * 70,
        "",
    ]

    for i, f in enumerate(session.findings, 1):
        sev = getattr(f.severity, "value", str(f.severity)).upper()
        lines += [
            f"\n{'─' * 60}",
            f"  Finding #{i:02d}  [{sev}]",
            f"  Title     : {f.title}",
            f"  Affected  : {getattr(f, 'affected_url', '') or getattr(f, 'affected_host', '')}",
            f"  Category  : {getattr(f, 'category', 'N/A')}",
            "",
            "  DESCRIPTION:",
            f"  {getattr(f, 'description', '')[:500]}",
            "",
            "  EVIDENCE:",
            f"  {getattr(f, 'evidence', '')[:300]}",
            "",
            "  REMEDIATION:",
            f"  {getattr(f, 'remediation', '')[:500]}",
        ]

    filepath.write_text("\n".join(lines), encoding="utf-8")
    logger.warning(f"reportlab unavailable, saved text report: {filepath}")
    return str(filepath)
