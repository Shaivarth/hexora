
import io
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)

ACCENT = colors.HexColor("#1FB6B0")
ACCENT_DARK = colors.HexColor("#0E2230")
RISK_COLORS = {
    "Critical": colors.HexColor("#E5484D"),
    "High": colors.HexColor("#F2994A"),
    "Medium": colors.HexColor("#F2C94C"),
    "Low": colors.HexColor("#2ECC71"),
}
INK = colors.HexColor("#1A2630")
MUTED = colors.HexColor("#5C6B73")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("ReportTitle", parent=ss["Title"], fontName="Helvetica-Bold",
                           fontSize=22, textColor=ACCENT_DARK, spaceAfter=2))
    ss.add(ParagraphStyle("ReportSub", parent=ss["Normal"], fontName="Helvetica",
                           fontSize=10, textColor=MUTED))
    ss.add(ParagraphStyle("Section", parent=ss["Heading2"], fontName="Helvetica-Bold",
                           fontSize=13, textColor=ACCENT_DARK, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontName="Helvetica",
                           fontSize=9.5, textColor=INK, leading=14))
    ss.add(ParagraphStyle("Mono", parent=ss["Normal"], fontName="Courier",
                           fontSize=8.5, textColor=INK, leading=12))
    ss.add(ParagraphStyle("RiskBullet", parent=ss["Normal"], fontName="Helvetica",
                           fontSize=9.5, textColor=INK, leading=14, leftIndent=10,
                           bulletIndent=0, spaceAfter=4))
    return ss


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(ACCENT_DARK)
    canvas.rect(0, A4[1] - 16 * mm, A4[0], 16 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(18 * mm, A4[1] - 11 * mm, "Hexora")
    canvas.setFont("Helvetica", 8.5)
    canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 11 * mm, "Static Malware Analysis Report")

    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 10 * mm,
    f"Generated {datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M IST')}")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#D8DEE2"))
    canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
    canvas.restoreState()


def build_report(scan: dict) -> bytes:
    buf = io.BytesIO()
    ss = _styles()

    frame = Frame(18 * mm, 20 * mm, A4[0] - 36 * mm, A4[1] - 42 * mm, id="main")
    doc = BaseDocTemplate(buf, pagesize=A4, title=f"Hexora Report — {scan['original_filename']}")
    doc.addPageTemplates([PageTemplate(id="standard", frames=[frame], onPage=_header_footer)])

    story = []

    story.append(Paragraph("Static Analysis Report", ss["ReportTitle"]))
    story.append(Paragraph(scan["original_filename"], ss["ReportSub"]))
    story.append(Spacer(1, 10))

    risk_color = RISK_COLORS.get(scan["risk_level"], MUTED)
    risk_table = Table(
        [[
            Paragraph(f"<b>Risk Score</b><br/><br/><font size=20>{scan['risk_score']}/100</font>", ss["Body"]),
            Paragraph(f"<b>Risk Level</b><br/><br/><font size=16 color='{risk_color.hexval()}'><b>{scan['risk_level']}</b></font>", ss["Body"]),
            Paragraph(f"<b>Scanned</b><br/><br/>{scan['uploaded_at']}", ss["Body"]),
        ]],
        colWidths=[55 * mm, 55 * mm, 65 * mm],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F7F8")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D8DEE2")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8DEE2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 4))

    story.append(Paragraph("File Identification", ss["Section"]))
    id_rows = [
        ["SHA-256", scan["sha256"]],
        ["SHA-1", scan["sha1"]],
        ["MD5", scan["md5"]],
        ["File size", f"{scan['file_size']:,} bytes"],
        ["MIME type", scan["mime_type"]],
        ["Category", scan["category"].title()],
        ["Shannon entropy", f"{scan['entropy']} / 8.0"],
    ]
    id_table = Table(
        [[Paragraph(f"<b>{k}</b>", ss["Body"]), Paragraph(v, ss["Mono"])] for k, v in id_rows],
        colWidths=[35 * mm, 140 * mm],
    )
    id_table.setStyle(TableStyle([
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E4E9EB")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#E4E9EB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(id_table)

    story.append(Paragraph("Risk Indicators", ss["Section"]))
    reasons = scan.get("risk_reasons") or []
    if reasons:
        for r in reasons:
            text = r["text"] if isinstance(r, dict) else r
            story.append(Paragraph(f"&bull;&nbsp; {_escape(text)}", ss["RiskBullet"]))
    else:
        story.append(Paragraph("No heuristic risk indicators were triggered.", ss["Body"]))

    story.append(Paragraph("Security Recommendations", ss["Section"]))
    for r in scan.get("recommendations") or []:
        story.append(Paragraph(f"&bull;&nbsp; {_escape(r)}", ss["RiskBullet"]))

    metadata = scan.get("metadata") or {}
    if metadata:
        story.append(Paragraph("Extracted Metadata", ss["Section"]))
        meta_text = _format_metadata(metadata)
        meta_html = _escape(meta_text).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")
        story.append(Paragraph(meta_html, ss["Mono"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "This report was produced entirely through static analysis. No code from the "
        "submitted file was executed at any point. Static heuristics can produce both "
        "false positives and false negatives, corroborate with dynamic/sandbox analysis "
        "and threat-intelligence lookups before taking irreversible action.",
        ss["ReportSub"],
    ))

    doc.build(story)
    return buf.getvalue()


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _format_metadata(meta: dict, indent: int = 0) -> str:
    lines = []
    prefix = "  " * indent
    for k, v in meta.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.append(_format_metadata(v, indent + 1))
        elif isinstance(v, list):
            preview = ", ".join(str(i) for i in v[:6])
            lines.append(f"{prefix}{k}: [{preview}]" if v else f"{prefix}{k}: []")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return "\n".join(lines)
