"""
PDF Report Generator — Professional penetration testing report.

Key design principles:
- ALL table cells use Paragraph() for automatic word-wrapping (no overflow)
- Full results included: no aggressive truncation
- Summary table includes evidence snippet
- Each finding on its own section with full detail
- KeepTogether prevents mid-finding page breaks
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
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

# Available page content width for A4 with 20mm margins each side
# A4 width = 595pt, margins = 20mm*2 = ~113pt → usable ~482pt
PAGE_W = 480


def _h(hex_color: str):
    """Convert hex string to reportlab HexColor."""
    from reportlab.lib import colors
    return colors.HexColor(hex_color)


def _safe(text: str, max_len: int = 10000) -> str:
    """Escape HTML for reportlab Paragraph. Preserves newlines as <br/>."""
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


def _p(text: str, style, max_len: int = 10000):
    """Create a Paragraph (safe for use inside Table cells — enables word wrap)."""
    from reportlab.platypus import Paragraph
    return Paragraph(_safe(text, max_len), style)


def _build_styles():
    """Build all paragraph styles used in the report."""
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()

    def s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_title": s("cover_title",
            fontSize=28, textColor=_h(WHITE), fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=8, leading=34),
        "cover_sub": s("cover_sub",
            fontSize=12, textColor=_h(ACCENT_BLUE), fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=4),
        "section": s("section",
            fontSize=15, textColor=_h(NAVY), fontName="Helvetica-Bold",
            spaceBefore=20, spaceAfter=8, leading=18),
        "subsection": s("subsection",
            fontSize=11, textColor=_h(BLUE), fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4),
        "body": s("body",
            fontSize=9, textColor=_h(BLACK), leading=13,
            alignment=TA_JUSTIFY, spaceAfter=4),
        "body_sm": s("body_sm",
            fontSize=8, textColor=_h(BLACK), leading=11, spaceAfter=2),
        "cell": s("cell",
            fontSize=7, textColor=_h(BLACK), leading=10),
        "cell_bold": s("cell_bold",
            fontSize=7, textColor=_h(BLACK), leading=10, fontName="Helvetica-Bold"),
        "cell_white": s("cell_white",
            fontSize=7, textColor=_h(WHITE), leading=10, fontName="Helvetica-Bold"),
        "cell_code": s("cell_code",
            fontSize=6, textColor=_h(BLACK), leading=9, fontName="Courier"),
        "small": s("small",
            fontSize=7, textColor=_h(GRAY), leading=10),
        "code": s("code",
            fontSize=7, fontName="Courier", textColor=_h(BLACK),
            backColor=_h("#f8f9fa"), leftIndent=6, rightIndent=6,
            spaceBefore=3, spaceAfter=3, leading=10,
            borderWidth=0.5, borderColor=_h("#dee2e6"), borderPadding=4),
        "remediation": s("remediation",
            fontSize=9, textColor=_h(BLACK), leading=13,
            backColor=_h("#f0faf4"), leftIndent=6, rightIndent=6,
            borderWidth=0.5, borderColor=_h(GREEN), borderPadding=4),
        "impact": s("impact",
            fontSize=9, textColor=_h(BLACK), leading=13,
            backColor=_h("#fff8e1"), leftIndent=6, rightIndent=6,
            borderWidth=0.5, borderColor=_h(YELLOW), borderPadding=4),
        "toc_entry": s("toc_entry",
            fontSize=10, textColor=_h(BLUE), leading=16),
        "footer": s("footer",
            fontSize=7, textColor=_h(GRAY), alignment=TA_CENTER),
    }


# ─── Page Header & Footer ────────────────────────────────────

def _page_header_footer(canvas, doc):
    """Draw header bar (pages 2+) and footer (all pages)."""
    from reportlab.lib.units import mm
    canvas.saveState()
    w, h = doc.pagesize

    if doc.page > 1:
        canvas.setFillColor(_h(DARK_NAVY))
        canvas.rect(0, h - 15*mm, w, 15*mm, fill=True, stroke=False)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(_h(WHITE))
        canvas.drawString(20*mm, h - 10*mm, "SECURITY ASSESSMENT REPORT  |  CONFIDENTIAL")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_h(ACCENT_BLUE))
        canvas.drawRightString(w - 20*mm, h - 10*mm, datetime.utcnow().strftime("%Y-%m-%d"))

    canvas.setFillColor(_h(LIGHT_GRAY))
    canvas.rect(0, 0, w, 10*mm, fill=True, stroke=False)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_h(GRAY))
    canvas.drawCentredString(w / 2, 3*mm, f"Page {doc.page}  |  Security Agent  |  CONFIDENTIAL")
    canvas.restoreState()


# ─── Cover Page ───────────────────────────────────────────────

def _draw_cover(story, session, targets, styles, pagesize):
    """Build cover page with full datetime and scan metadata."""
    from reportlab.lib.units import mm
    from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, HRFlowable, PageBreak

    tz_vn = timezone(timedelta(hours=7))
    now_utc = datetime.utcnow()
    now_vn  = datetime.now(tz_vn)

    scan_start = getattr(session, "started_at", None)
    scan_end   = getattr(session, "completed_at", None)
    start_str  = scan_start.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(scan_start, datetime) else now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    if isinstance(scan_end, datetime) and isinstance(scan_start, datetime):
        dur = scan_end - scan_start
        ts = int(dur.total_seconds())
        duration_str = f"{ts // 3600}h {(ts % 3600) // 60}m {ts % 60}s"
        end_str = scan_end.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        end_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        duration_str = "N/A"

    sev = session.severity_summary
    cn, hn, mn, ln = sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0)
    risk = "CRITICAL" if cn else "HIGH" if hn else "MEDIUM" if mn else "LOW" if ln else "INFO"
    risk_c = SEV_COLORS.get(risk.lower(), GRAY)

    story.append(Spacer(1, 30))
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["cover_title"]))
    story.append(Paragraph("AI-Powered Penetration Testing", styles["cover_sub"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="50%", thickness=2, color=_h(ACCENT_BLUE), spaceAfter=15))

    # Cover metadata table — use Paragraph cells for wrapping
    rows = [
        ["Target(s)",        _p(targets, styles["cell"])],
        ["Report Date",      _p(now_utc.strftime("%A, %B %d, %Y"), styles["cell"])],
        ["Report Time UTC",  _p(now_utc.strftime("%H:%M:%S UTC"), styles["cell"])],
        ["Report Time VN",   _p(now_vn.strftime("%H:%M:%S UTC+7 (Vietnam)"), styles["cell"])],
        ["Scan Started",     _p(start_str, styles["cell"])],
        ["Scan Ended",       _p(end_str, styles["cell"])],
        ["Scan Duration",    _p(duration_str, styles["cell"])],
        ["Session ID",       _p(session.id[:16], styles["cell"])],
        ["Scan Mode",        _p(getattr(session, "scan_mode", "N/A").upper(), styles["cell"])],
        ["Total Findings",   _p(str(len(session.findings)), styles["cell"])],
        ["Overall Risk",     Paragraph(f'<font color="{risk_c}"><b>{risk}</b></font>', styles["cell"])],
    ]
    # Convert labels to Paragraph too
    from reportlab.platypus import Paragraph as P
    rows = [[P(f'<b>{r[0]}</b>', styles["cell"]), r[1]] for r in rows]

    tbl = Table(rows, colWidths=[120, PAGE_W - 120])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _h(NAVY)),
        ("BACKGROUND", (1, 0), (1, -1), _h("#1e2d40")),
        ("TEXTCOLOR", (0, 0), (0, -1), _h(ACCENT_BLUE)),
        ("TEXTCOLOR", (1, 0), (1, -1), _h(WHITE)),
        ("GRID", (0, 0), (-1, -1), 0.5, _h("#2c3e50")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 20))

    # Severity breakdown on cover
    if any(sev.values()):
        sev_hdr = [
            [P('<b>Severity</b>', styles["cell_white"]),
             P('<b>Count</b>', styles["cell_white"]),
             P('<b>CVSS Range</b>', styles["cell_white"])],
        ]
        sev_rows_data = [
            ("critical", "9.0 - 10.0"), ("high", "7.0 - 8.9"),
            ("medium", "4.0 - 6.9"), ("low", "1.0 - 3.9"), ("info", "Informational"),
        ]
        sev_body = []
        for sk, cvss in sev_rows_data:
            c = sev.get(sk, 0)
            if c > 0:
                sev_body.append([
                    P(f'<font color="{SEV_COLORS[sk]}"><b>{sk.upper()}</b></font>', styles["cell"]),
                    P(str(c), styles["cell"]),
                    P(cvss, styles["cell"]),
                ])
        if sev_body:
            stbl = Table(sev_hdr + sev_body, colWidths=[100, 60, PAGE_W - 160])
            stbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), _h(BLUE)),
                ("GRID", (0, 0), (-1, -1), 0.5, _h(GRAY)),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(stbl)

    story.append(Spacer(1, 25))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(NAVY)))
    story.append(Paragraph(
        "<i>This report is confidential and intended solely for authorized recipients.</i>",
        styles["small"],
    ))
    story.append(PageBreak())


# ─── Single Finding ──────────────────────────────────────────

def _draw_finding(i: int, f: Any, styles, story):
    """Render one finding with full details. All text uses Paragraph for wrapping."""
    from reportlab.platypus import (
        Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    )

    sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
    sev_color = SEV_COLORS.get(sev, GRAY)
    sev_bg    = SEV_BG.get(sev, LIGHT_GRAY)

    elements = []

    # ── Header bar ──
    hdr = Table(
        [[Paragraph(f'<b>#{i:02d}</b>', styles["cell_white"]),
          Paragraph(f'<b>{_safe(f.title)}</b>', styles["cell_white"]),
          Paragraph(f'<b>{sev.upper()}</b>', styles["cell_white"])]],
        colWidths=[35, PAGE_W - 100, 65],
    )
    hdr.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), _h(NAVY)),
        ("BACKGROUND", (2, 0), (2, 0), _h(sev_color)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (2, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(hdr)

    # ── Metadata table ──
    affected = str(getattr(f, "affected_url", "") or getattr(f, "affected_host", "") or "N/A")
    meta = [
        ["Severity",     Paragraph(f'<font color="{sev_color}"><b>{sev.upper()}</b></font>', styles["cell"])],
        ["Confidence",   _p(str(getattr(f, "confidence", "medium")).upper(), styles["cell"])],
        ["Category",     _p(str(getattr(f, "category", "") or "N/A"), styles["cell"])],
        ["Affected",     _p(affected, styles["cell"])],
    ]
    if getattr(f, "cvss_score", None):
        meta.append(["CVSS Score", _p(f"{f.cvss_score:.1f} / 10.0", styles["cell"])])
    if getattr(f, "cve_ids", None):
        meta.append(["CVE IDs", _p(", ".join(f.cve_ids[:10]), styles["cell"])])
    if getattr(f, "tool_source", ""):
        meta.append(["Tool", _p(f.tool_source, styles["cell"])])
    if getattr(f, "references", None):
        refs_text = "\n".join(str(r) for r in f.references[:5])
        meta.append(["References", _p(refs_text, styles["cell"])])

    # Convert labels to Paragraph
    meta = [[Paragraph(f'<b>{r[0]}</b>', styles["cell_bold"]), r[1]] for r in meta]

    mtbl = Table(meta, colWidths=[80, PAGE_W - 80])
    mtbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _h(sev_bg)),
        ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(mtbl)
    elements.append(Spacer(1, 4))

    # ── Description ──
    desc = str(getattr(f, "description", "") or "")
    if desc:
        impact = ""
        if "**Impact:**" in desc:
            parts = desc.split("**Impact:**", 1)
            desc = parts[0].strip()
            impact = parts[1].strip()
        elif "Impact:" in desc:
            parts = desc.split("Impact:", 1)
            desc = parts[0].strip()
            impact = parts[1].strip()

        elements.append(Paragraph("<b>Description</b>", styles["subsection"]))
        elements.append(Paragraph(_safe(desc), styles["body"]))

        if impact:
            elements.append(Paragraph(f"<b>Impact:</b> {_safe(impact)}", styles["impact"]))
            elements.append(Spacer(1, 3))

    # ── Evidence ──
    evidence = str(getattr(f, "evidence", "") or "")
    if evidence:
        elements.append(Paragraph("<b>Evidence / Proof of Concept</b>", styles["subsection"]))
        elements.append(Paragraph(_safe(evidence), styles["code"]))
        elements.append(Spacer(1, 3))

    # ── Remediation ──
    remediation = str(getattr(f, "remediation", "") or "")
    if remediation:
        elements.append(Paragraph("<b>Remediation</b>", styles["subsection"]))
        elements.append(Paragraph(_safe(remediation), styles["remediation"]))
        elements.append(Spacer(1, 3))

    elements.append(HRFlowable(width="100%", thickness=0.5, color=_h(LIGHT_GRAY), spaceAfter=8))

    # Try to keep the finding header + metadata together
    if len(elements) > 4:
        story.append(KeepTogether(elements[:4]))  # header + meta table
        story.extend(elements[4:])
    else:
        story.extend(elements)


# ─── Main Entry Point ────────────────────────────────────────

def generate_pdf_report(session: Any, output_dir: str = "./reports") -> str:
    """
    Generate a professional penetration testing PDF report.
    All table cells use Paragraph for word-wrapping — no overflow.
    """
    try:
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
        topMargin=20 * mm,
        bottomMargin=15 * mm,
        title="Security Assessment Report",
        author="Security Agent",
        subject="Penetration Testing Report",
    )

    styles = _build_styles()
    story  = []

    targets = ", ".join(t.value for t in session.targets) if hasattr(session, "targets") else "N/A"

    # ═══════════════════════════════════════════════════════
    # 1. Cover Page
    # ═══════════════════════════════════════════════════════
    _draw_cover(story, session, targets, styles, A4)

    # ═══════════════════════════════════════════════════════
    # 2. Table of Contents
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("Table of Contents", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))
    toc = [
        ("1.", "Executive Summary"),
        ("2.", f"Findings Summary (with Evidence) — {len(session.findings)} findings"),
        ("3.", "Detailed Findings"),
        ("4.", "Remediation Roadmap"),
        ("5.", "Tool Execution Log"),
        ("6.", "Methodology"),
    ]
    for num, title in toc:
        story.append(Paragraph(f'<b>{num}</b>&nbsp;&nbsp;{title}', styles["toc_entry"]))
    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 3. Executive Summary
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))

    sev = session.severity_summary
    cn = sev.get("critical", 0)
    hn = sev.get("high", 0)
    mn = sev.get("medium", 0)
    ln = sev.get("low", 0)
    info_n = sev.get("info", 0)
    total_n = len(session.findings)

    risk = "CRITICAL" if cn else "HIGH" if hn else "MEDIUM" if mn else "LOW" if ln else "INFO"
    risk_c = SEV_COLORS.get(risk.lower(), GRAY)

    story.append(Paragraph(
        f"A comprehensive security assessment was conducted against <b>{_safe(targets)}</b>. "
        f"The assessment identified <b>{total_n}</b> security findings. "
        f'Overall risk: <font color="{risk_c}"><b>{risk}</b></font>.',
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    # Severity distribution table
    sev_hdr = [[
        Paragraph('<b>Severity</b>', styles["cell_white"]),
        Paragraph('<b>Count</b>', styles["cell_white"]),
    ]]
    sev_body = []
    for sk, label in [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO")]:
        c = sev.get(sk, 0)
        sev_body.append([
            Paragraph(f'<font color="{SEV_COLORS[sk]}"><b>{label}</b></font>', styles["cell"]),
            Paragraph(str(c), styles["cell"]),
        ])
    sev_tbl = Table(sev_hdr + sev_body, colWidths=[120, 80])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
        ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(sev_tbl)
    story.append(Spacer(1, 8))

    # CVSS stats
    cvss_scores = [f.cvss_score for f in session.findings if getattr(f, "cvss_score", None)]
    if cvss_scores:
        story.append(Paragraph(
            f"<b>CVSS:</b> Average <b>{sum(cvss_scores)/len(cvss_scores):.1f}</b>, "
            f"Max <b>{max(cvss_scores):.1f}</b> / 10.0",
            styles["body"],
        ))

    # Critical findings callout
    crits = [f for f in session.findings if getattr(f.severity, "value", "") == "critical"]
    if crits:
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f'<font color="{SEV_COLORS["critical"]}"><b>Critical Findings Requiring Immediate Action:</b></font>',
            styles["body"],
        ))
        for cf in crits[:10]:
            story.append(Paragraph(
                f"&nbsp;&nbsp;- <b>{_safe(cf.title)}</b> ({_safe(str(getattr(cf, 'affected_url', '') or getattr(cf, 'affected_host', '')))})",
                styles["body_sm"],
            ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 4. Findings Summary Table (WITH evidence snippet)
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("2. Findings Summary", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))

    if session.findings:
        # Header row
        hdr = [[
            Paragraph('<b>#</b>', styles["cell_white"]),
            Paragraph('<b>Title</b>', styles["cell_white"]),
            Paragraph('<b>Sev</b>', styles["cell_white"]),
            Paragraph('<b>Affected</b>', styles["cell_white"]),
            Paragraph('<b>Evidence (snippet)</b>', styles["cell_white"]),
        ]]

        # Data rows — all cells are Paragraph for word-wrapping
        data_rows = []
        for idx, f in enumerate(session.findings, 1):
            sev_val = getattr(f.severity, "value", str(f.severity)).lower()
            sc = SEV_COLORS.get(sev_val, GRAY)

            evidence_raw = str(getattr(f, "evidence", "") or "")
            # Take first 200 chars of evidence for the summary
            evidence_snip = evidence_raw[:200] + ("..." if len(evidence_raw) > 200 else "")

            data_rows.append([
                Paragraph(str(idx), styles["cell"]),
                _p(str(f.title), styles["cell"]),
                Paragraph(f'<font color="{sc}"><b>{sev_val.upper()}</b></font>', styles["cell"]),
                _p(str(getattr(f, "affected_url", "") or getattr(f, "affected_host", "") or "N/A"), styles["cell"]),
                _p(evidence_snip or "N/A", styles["cell_code"]),
            ])

        # Column widths: # | Title | Sev | Affected | Evidence
        col_w = [20, 120, 40, 110, PAGE_W - 290]
        ftbl = Table(hdr + data_rows, colWidths=col_w, repeatRows=1)
        ftbl_style = [
            ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        # Alternating row backgrounds
        for ri in range(len(session.findings)):
            row = ri + 1
            bg = WHITE if row % 2 == 1 else LIGHT_GRAY
            ftbl_style.append(("BACKGROUND", (0, row), (-1, row), _h(bg)))

        ftbl.setStyle(TableStyle(ftbl_style))
        story.append(ftbl)
    else:
        story.append(Paragraph("No security findings were identified.", styles["body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 5. Detailed Findings (full content)
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("3. Detailed Findings", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))

    for i, f in enumerate(session.findings, 1):
        _draw_finding(i, f, styles, story)

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 6. Remediation Roadmap
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("4. Remediation Roadmap", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))

    def _by_sev(sevs):
        return [f for f in session.findings
                if getattr(f.severity, "value", str(f.severity)).lower() in sevs]

    roadmap = [
        ("Immediate Action (0-7 days)",  ["critical"],    RED,    "Address immediately. Severe risk, may be actively exploitable."),
        ("Short-Term (1-4 weeks)",       ["high"],        ORANGE, "Remediate in the next sprint or iteration."),
        ("Mid-Term (1-3 months)",        ["medium"],      YELLOW, "Address in near term to prevent escalation."),
        ("Long-Term (3-6 months)",       ["low", "info"], BLUE,   "Track and address in regular hardening cycles."),
    ]

    for title, sevs, color, guidance in roadmap:
        matching = _by_sev(sevs)
        if not matching:
            continue
        story.append(Paragraph(f'<font color="{color}"><b>{title}</b></font>', styles["subsection"]))
        story.append(Paragraph(guidance, styles["body"]))

        # Table of findings in this priority
        road_rows = [[
            Paragraph('<b>#</b>', styles["cell_white"]),
            Paragraph('<b>Finding</b>', styles["cell_white"]),
            Paragraph('<b>Remediation</b>', styles["cell_white"]),
        ]]
        for idx, mf in enumerate(matching, 1):
            rem = str(getattr(mf, "remediation", "") or "N/A")
            # Show first 300 chars of remediation
            rem_short = rem[:300] + ("..." if len(rem) > 300 else "")
            road_rows.append([
                Paragraph(str(idx), styles["cell"]),
                _p(str(mf.title), styles["cell_bold"]),
                _p(rem_short, styles["cell"]),
            ])
        rtbl = Table(road_rows, colWidths=[20, 160, PAGE_W - 180], repeatRows=1)
        rtbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _h(color)),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(rtbl)
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 7. Tool Execution Log
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("5. Tool Execution Log", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))

    if getattr(session, "tool_executions", None):
        log_hdr = [[
            Paragraph('<b>Tool</b>', styles["cell_white"]),
            Paragraph('<b>Phase</b>', styles["cell_white"]),
            Paragraph('<b>Status</b>', styles["cell_white"]),
            Paragraph('<b>Duration</b>', styles["cell_white"]),
        ]]
        log_rows = []
        for e in session.tool_executions[:80]:
            status_str = getattr(e, "status", "").upper()
            phase_str = e.phase.value if hasattr(e.phase, "value") else str(e.phase)
            dur_str = f"{e.duration_seconds:.1f}s"
            # Color-code status
            if status_str in ("FAILED", "ERROR"):
                status_p = Paragraph(f'<font color="{RED}"><b>{status_str}</b></font>', styles["cell"])
            elif status_str == "COMPLETED":
                status_p = Paragraph(f'<font color="{GREEN}"><b>{status_str}</b></font>', styles["cell"])
            else:
                status_p = _p(status_str, styles["cell"])

            log_rows.append([
                _p(e.tool_name, styles["cell"]),
                _p(phase_str, styles["cell"]),
                status_p,
                _p(dur_str, styles["cell"]),
            ])

        ltbl = Table(log_hdr + log_rows, colWidths=[120, 100, 90, 70], repeatRows=1)
        ltbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _h(DARK_NAVY)),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(LIGHT_GRAY)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_h(WHITE), _h(LIGHT_GRAY)]),
        ]))
        story.append(ltbl)
    else:
        story.append(Paragraph("No tool execution data available.", styles["body"]))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # 8. Methodology
    # ═══════════════════════════════════════════════════════
    story.append(Paragraph("6. Methodology", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(ACCENT_BLUE), spaceAfter=8))
    story.append(Paragraph(
        "The assessment followed a structured methodology aligned with OWASP, PTES, and NIST SP 800-115:",
        styles["body"],
    ))
    for phase, desc in [
        ("Reconnaissance", "Subdomain enumeration, DNS resolution, port scanning, technology fingerprinting, WAF detection."),
        ("Vulnerability Scanning", "Nuclei CVE templates, Nikto, TestSSL, email security checks (SPF/DKIM/DMARC), secret scanning."),
        ("Exploitation", "Controlled exploitation to confirm findings and assess actual impact."),
        ("Reporting", "AI-powered analysis, severity classification, risk assessment, remediation guidance."),
    ]:
        story.append(Paragraph(f"<b>{phase}:</b> {_safe(desc)}", styles["body"]))

    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=1, color=_h(LIGHT_GRAY)))
    story.append(Paragraph(
        f"<i>Security Agent v1.0.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | Confidential</i>",
        styles["footer"],
    ))

    # ═══════════════════════════════════════════════════════
    # Build
    # ═══════════════════════════════════════════════════════
    doc.build(story, onFirstPage=_page_header_footer, onLaterPages=_page_header_footer)
    logger.info(f"PDF report saved: {filepath}")
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
        f"  Session : {session.id[:16]}",
        f"  Targets : {', '.join(t.value for t in session.targets)}",
        f"  Findings: {len(session.findings)}",
        "=" * 70, "",
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
            f"  {getattr(f, 'description', '')}",
            "",
            "  EVIDENCE:",
            f"  {getattr(f, 'evidence', '')}",
            "",
            "  REMEDIATION:",
            f"  {getattr(f, 'remediation', '')}",
        ]

    filepath.write_text("\n".join(lines), encoding="utf-8")
    logger.warning(f"reportlab unavailable — text report: {filepath}")
    return str(filepath)
