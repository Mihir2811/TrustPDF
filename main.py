"""
TrustPDF Enhanced — FastAPI Server with PDF Report Generation
PDF Security Analysis Tool with HTML/PDF Report Export
"""

import os
import io
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ReportLab imports for PDF report generation
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.platypus.flowables import Flowable
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics import renderPDF

# Import PDF detector class
from app import PDFTamperingDetector

# ─────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────

app = FastAPI(title="TrustPDF Enhanced", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("static", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ─────────────────────────────────────────────
# Color Palette  —  matches index.html gov style
# ─────────────────────────────────────────────

BRAND_DARK      = colors.HexColor("#FFFFFF")     # page background → white
BRAND_SURFACE   = colors.HexColor("#F3F4F6")     # panel bg (gov section header)
BRAND_BORDER    = colors.HexColor("#B1B4B6")     # gov-border
BRAND_ACCENT    = colors.HexColor("#2B5797")     # gov-blue (primary)
BRAND_GREEN     = colors.HexColor("#00703C")     # gov-success
BRAND_YELLOW    = colors.HexColor("#F59E0B")     # amber warning
BRAND_RED       = colors.HexColor("#C41E3A")     # gov-red
BRAND_TEXT      = colors.HexColor("#1D2939")     # gov-text
BRAND_MUTED     = colors.HexColor("#505A5F")     # gov-text-secondary
BRAND_BLUE_DARK = colors.HexColor("#1A3A5C")     # gov-blue-dark (header)
BRAND_GOLD      = colors.HexColor("#B8860B")     # gov-gold
WHITE           = colors.HexColor("#FFFFFF")


# ─────────────────────────────────────────────
# Custom Flowables
# ─────────────────────────────────────────────

class ColorBar(Flowable):
    """Full-width header bar — gov-blue-dark with gold bottom border."""
    def __init__(self, height=48, color=BRAND_BLUE_DARK, gold_strip=True):
        super().__init__()
        self.bar_height = height
        self.color = color
        self.gold_strip = gold_strip
        self.width = 0

    def wrap(self, availWidth, availHeight):
        self.width = availWidth
        return availWidth, self.bar_height

    def draw(self):
        c = self.canv
        # Main bar
        c.setFillColor(self.color)
        c.rect(0, 0, self.width, self.bar_height, fill=1, stroke=0)
        # Gold bottom strip (like gov-gold border-bottom)
        if self.gold_strip:
            c.setFillColor(BRAND_GOLD)
            c.rect(0, 0, self.width, 3, fill=1, stroke=0)


class SectionHeader(Flowable):
    """Gov-style section header: light grey bg, bold blue bottom border, dark text."""
    def __init__(self, title, color=BRAND_ACCENT):
        super().__init__()
        self.title = title
        self.color = color
        self.width = 0
        self.height = 30

    def wrap(self, availWidth, availHeight):
        self.width = availWidth
        return availWidth, self.height

    def draw(self):
        c = self.canv
        # Light grey background (gov-section-header)
        c.setFillColor(BRAND_SURFACE)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        # Border top in gov-blue
        c.setFillColor(self.color)
        c.rect(0, self.height - 3, self.width, 3, fill=1, stroke=0)
        # Bottom border line
        c.setStrokeColor(BRAND_BORDER)
        c.setLineWidth(0.5)
        c.line(0, 0, self.width, 0)
        # Title text — dark, bold, uppercase
        c.setFillColor(BRAND_TEXT)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(12, 10, self.title.upper())


class RiskBadge(Flowable):
    """Gov-style risk badge: white card, coloured border, tag-style label."""
    def __init__(self, level, failed, total):
        super().__init__()
        self.level = level
        self.failed = failed
        self.total = total
        self.width = 175
        self.height = 82

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        c = self.canv
        color_map = {
            "HIGH RISK":   BRAND_RED,
            "MEDIUM RISK": BRAND_YELLOW,
            "LOW RISK":    BRAND_GREEN,
        }
        level_key = "LOW RISK"
        for k in color_map:
            if k in self.level.upper():
                level_key = k
                break
        accent = color_map[level_key]

        # White card with coloured border (like gov-tag style)
        c.setFillColor(WHITE)
        c.setStrokeColor(accent)
        c.setLineWidth(2)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=1)

        # Coloured top strip
        c.setFillColor(accent)
        c.rect(0, self.height - 6, self.width, 6, fill=1, stroke=0)

        # Risk level label (large, coloured)
        c.setFillColor(accent)
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(self.width / 2, 50, level_key)

        # Checks failed text
        c.setFillColor(BRAND_MUTED)
        c.setFont("Helvetica", 9)
        c.drawCentredString(self.width / 2, 34, f"{self.failed} of {self.total} checks failed")

        # Divider
        c.setStrokeColor(BRAND_BORDER)
        c.setLineWidth(0.5)
        c.line(12, 26, self.width - 12, 26)

        # Pass count
        passed = self.total - self.failed
        c.setFillColor(BRAND_GREEN)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(self.width / 2, 12, f"{passed}/{self.total} PASSED")


class CheckRow(Flowable):
    """Gov-style security check row — white bg, border-bottom, coloured left strip."""
    def __init__(self, text, status):
        super().__init__()
        self.text = text
        self.status = status
        self.width = 0
        self.height = 24

    def wrap(self, availWidth, availHeight):
        self.width = availWidth
        return availWidth, self.height

    def draw(self):
        c = self.canv
        status_map = {
            "pass":    (BRAND_GREEN,  "PASS"),
            "fail":    (BRAND_RED,    "FAIL"),
            "warning": (BRAND_YELLOW, "WARN"),
            "info":    (BRAND_ACCENT, "INFO"),
        }
        accent, label = status_map.get(self.status, (BRAND_MUTED, "NOTE"))

        # White row background
        c.setFillColor(WHITE)
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)

        # Coloured left strip (like gov-finding border-left)
        c.setFillColor(accent)
        c.rect(0, 0, 4, self.height, fill=1, stroke=0)

        # Bottom border
        c.setStrokeColor(BRAND_BORDER)
        c.setLineWidth(0.4)
        c.line(0, 0, self.width, 0)

        # Status label pill (small coloured box)
        pill_w = 28
        c.setFillColor(accent)
        c.rect(10, 7, pill_w, 11, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 6)
        c.drawCentredString(10 + pill_w / 2, 10, label)

        # Check text
        c.setFillColor(BRAND_TEXT)
        c.setFont("Helvetica", 9)
        display = self.text if len(self.text) < 105 else self.text[:102] + "..."
        c.drawString(46, 9, display)


# ─────────────────────────────────────────────
# PDF Report Generator
# ─────────────────────────────────────────────

def generate_pdf_report(analysis_data: Dict[str, Any]) -> bytes:
    """
    Generate a professional PDF security report from analysis_data.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    PAGE_W, PAGE_H = A4
    MARGIN = 20 * mm

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="TrustPDF Security Report",
        author="TrustPDF Enhanced",
    )

    styles = getSampleStyleSheet()

    # ── Custom text styles  (gov light theme) ──
    def S(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=styles[parent], **kw)

    sTitle    = S("sTitle",    "Title",   fontSize=22, textColor=WHITE,
                  fontName="Helvetica-Bold", spaceAfter=4, alignment=TA_LEFT)
    sSubtitle = S("sSubtitle", fontSize=11, textColor=colors.HexColor("#071F36"),
                  fontName="Helvetica", spaceAfter=0, alignment=TA_LEFT)
    sBody     = S("sBody",     fontSize=9,  textColor=BRAND_TEXT,
                  fontName="Helvetica", leading=14, spaceAfter=4)
    sLabel    = S("sLabel",    fontSize=8,  textColor=BRAND_MUTED,
                  fontName="Helvetica-Bold", spaceAfter=2, textTransform="uppercase")
    sValue    = S("sValue",    fontSize=9,  textColor=BRAND_TEXT,
                  fontName="Helvetica", spaceAfter=6)
    sWarning  = S("sWarning",  fontSize=9,  textColor=BRAND_RED,
                  fontName="Helvetica-Bold", spaceAfter=4)
    sNote     = S("sNote",     fontSize=8,  textColor=BRAND_MUTED,
                  fontName="Helvetica-Oblique", spaceAfter=4)

    story: List[Any] = []
    CONTENT_W = PAGE_W - 2 * MARGIN

    # ────────────────────────────────────────
    # HEADER BLOCK  (gov-blue-dark + gold strip)
    # ────────────────────────────────────────
    story.append(ColorBar(height=52, color=BRAND_BLUE_DARK, gold_strip=True))
    story.append(Spacer(1, 10))

    story.append(Paragraph("TrustPDF", sTitle))
    story.append(Paragraph("Document Security Verification Service  •  Security Analysis Report", sSubtitle))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BORDER, spaceAfter=12))

    # ────────────────────────────────────────
    # FILE INFO + RISK BADGE (side by side via Table)
    # ────────────────────────────────────────
    fi      = analysis_data.get("file_info", {})
    ra      = analysis_data.get("risk_assessment", {})
    qs      = analysis_data.get("quick_stats", {})
    verdict = analysis_data.get("final_verdict", {})
    now_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S UTC")

    info_lines = [
        Paragraph(f"<b>Filename</b>", sLabel),
        Paragraph(fi.get("name", "N/A"), sValue),
        Paragraph(f"<b>File Size</b>", sLabel),
        Paragraph(fi.get("size_formatted", "N/A"), sValue),
        Paragraph(f"<b>SHA-256</b>", sLabel),
        Paragraph(f'<font size="7" color="#505A5F">{fi.get("hash", "N/A")}</font>', sBody),
        Paragraph(f"<b>Analyzed At</b>", sLabel),
        Paragraph(now_str, sValue),
    ]

    badge = RiskBadge(
        level=ra.get("level", "UNKNOWN"),
        failed=verdict.get("failed_checks", 0),
        total=verdict.get("total_checks", 8),
    )

    info_table = Table(
        [[info_lines, badge]],
        colWidths=[CONTENT_W - 195, 180],
    )
    info_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN",  (1, 0), (1, 0),  "CENTER"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 14))

    # ────────────────────────────────────────
    # QUICK STATS ROW
    # ────────────────────────────────────────
    story.append(SectionHeader("Quick Statistics", BRAND_ACCENT))
    story.append(Spacer(1, 8))

    def stat_cell(label, value, accent=BRAND_ACCENT):
        return [
            Paragraph(f'<font color="#505A5F" size="8">{label}</font>', sNote),
            Paragraph(f'<font color="{accent.hexval()}" size="18"><b>{value}</b></font>', sBody),
        ]

    js_count  = qs.get("javascript_blocks", 0)
    emb_count = qs.get("embedded_files", 0)
    inc_count = qs.get("incremental_updates", 0)
    fail_cnt  = qs.get("failed_security_checks", 0)

    js_color  = BRAND_RED    if js_count > 0   else BRAND_GREEN
    emb_color = BRAND_YELLOW if emb_count > 0  else BRAND_GREEN
    inc_color = BRAND_YELLOW if inc_count > 0  else BRAND_GREEN
    fai_color = BRAND_RED    if fail_cnt >= 4  else (BRAND_YELLOW if fail_cnt >= 2 else BRAND_GREEN)

    stats_data = [[
        stat_cell("Incremental Updates", inc_count, inc_color),
        stat_cell("Embedded Files",      emb_count, emb_color),
        stat_cell("JavaScript Blocks",   js_count,  js_color),
        stat_cell("Failed Checks",       fail_cnt,  fai_color),
    ]]

    col_w = CONTENT_W / 4
    stats_table = Table(stats_data, colWidths=[col_w] * 4)
    stats_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
        ("BOX",           (0, 0), (-1, -1), 1, BRAND_BORDER),
        ("LINEBEFORE",    (1, 0), (-1, -1), 1, BRAND_BORDER),
        ("LINEABOVE",     (0, 0), (-1, 0),  2, BRAND_ACCENT),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 16))

    # ────────────────────────────────────────
    # FINAL VERDICT CHECKLIST
    # ────────────────────────────────────────
    story.append(SectionHeader("Security Verdict  —  8-Point Checklist", BRAND_ACCENT))
    story.append(Spacer(1, 6))

    verdict_summary = verdict.get("summary", "")
    if verdict_summary:
        story.append(Paragraph(verdict_summary, sBody))
        story.append(Spacer(1, 6))

    detailed_checks = verdict.get("detailed_checks", [])
    if detailed_checks:
        for chk in detailed_checks:
            story.append(CheckRow(chk.get("text", ""), chk.get("status", "info")))
            story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No detailed check data available.", sNote))

    story.append(Spacer(1, 14))

    # ────────────────────────────────────────
    # METADATA TABLE
    # ────────────────────────────────────────
    story.append(SectionHeader("Document Metadata", BRAND_ACCENT))
    story.append(Spacer(1, 8))

    meta_table_data = analysis_data.get("metadata", {}).get("table", [])
    if meta_table_data:
        rows = [[
            Paragraph(f'<b><font color="#505A5F" size="8">{row["key"]}</font></b>', sLabel),
            Paragraph(f'<font size="9">{row["value"]}</font>', sBody),
        ] for row in meta_table_data]

        meta_tbl = Table(rows, colWidths=[CONTENT_W * 0.35, CONTENT_W * 0.65])
        meta_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, BRAND_SURFACE]),
            ("GRID",           (0, 0), (-1, -1), 0.5, BRAND_BORDER),
            ("BACKGROUND",     (0, 0), (-1, -1), BRAND_SURFACE),
            ("BACKGROUND",     (1, 0), (1, -1),  WHITE),
            ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",     (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
            ("LEFTPADDING",    (0, 0), (-1, -1), 10),
        ]))
        story.append(meta_tbl)
    else:
        story.append(Paragraph("No metadata available.", sNote))

    story.append(Spacer(1, 16))

    # ────────────────────────────────────────
    # SECURITY FINDINGS
    # ────────────────────────────────────────
    findings = analysis_data.get("findings", [])
    if findings:
        story.append(SectionHeader("Security Findings", BRAND_RED))
        story.append(Spacer(1, 8))

        type_map = {
            "critical": (BRAND_RED,    "CRITICAL"),
            "error":    (BRAND_RED,    "ERROR"),
            "warning":  (BRAND_YELLOW, "WARNING"),
            "info":     (BRAND_ACCENT, "INFO"),
        }

        for f in findings:
            ftype  = f.get("type", "info")
            ftitle = f.get("title", "")
            fdesc  = f.get("description", "")
            fcolor, flabel = type_map.get(ftype, (BRAND_MUTED, "NOTE"))

            badge_text = f'<font color="{fcolor.hexval()}" size="7"><b> {flabel} </b></font>'
            row_data = [[
                Paragraph(f'{badge_text}  <font size="9"><b>{ftitle}</b></font>', sBody),
                Paragraph(f'<font size="8">{fdesc}</font>', sBody),
            ]]
            row_tbl = Table(row_data, colWidths=[CONTENT_W * 0.28, CONTENT_W * 0.72])
            row_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.5, BRAND_BORDER),
                ("LINELEFT",      (0, 0), (0, -1),  4, fcolor),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            story.append(row_tbl)
            story.append(Spacer(1, 2))

        story.append(Spacer(1, 12))

    # ────────────────────────────────────────
    # RECOMMENDATIONS
    # ────────────────────────────────────────
    recommendations = analysis_data.get("recommendations", [])
    if recommendations:
        story.append(SectionHeader("Recommendations", BRAND_GREEN))
        story.append(Spacer(1, 8))

        for i, rec in enumerate(recommendations, 1):
            rec_data = [[
                Paragraph(f'<font color="{BRAND_GREEN.hexval()}" size="9"><b>{i}</b></font>', sBody),
                Paragraph(f'<font size="9">{rec}</font>', sBody),
            ]]
            rec_tbl = Table(rec_data, colWidths=[20, CONTENT_W - 20])
            rec_tbl.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ]))
            story.append(rec_tbl)

        story.append(Spacer(1, 12))

    # ────────────────────────────────────────
    # EMBEDDED FILES & JAVASCRIPT
    # ────────────────────────────────────────
    sec = analysis_data.get("security_details", {})

    embedded_files = sec.get("embedded_files", [])
    if embedded_files:
        story.append(SectionHeader("Embedded Files", BRAND_YELLOW))
        story.append(Spacer(1, 6))

        ef_rows = [
            [Paragraph("<b>Filename</b>", sLabel), Paragraph("<b>Size</b>", sLabel)]
        ] + [
            [Paragraph(ef["name"], sBody), Paragraph(ef["size_formatted"], sBody)]
            for ef in embedded_files
        ]
        ef_tbl = Table(ef_rows, colWidths=[CONTENT_W * 0.75, CONTENT_W * 0.25])
        ef_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  BRAND_SURFACE),
            ("BACKGROUND",    (0, 1), (-1, -1), WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, BRAND_SURFACE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, BRAND_BORDER),
            ("LINEABOVE",     (0, 0), (-1, 0),  2, BRAND_ACCENT),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ]))
        story.append(ef_tbl)
        story.append(Spacer(1, 12))

    js_payloads = sec.get("javascript_payloads", [])
    if js_payloads:
        story.append(SectionHeader("JavaScript Payloads Detected", BRAND_RED))
        story.append(Spacer(1, 6))

        for js in js_payloads:
            preview = js.get("preview", "")
            story.append(Paragraph(
                f'<font size="8" color="{BRAND_RED.hexval()}"><b>Payload #{js["id"]}</b></font>  '
                f'<font size="7" color="{BRAND_MUTED.hexval()}">({js["size"]} bytes)</font>',
                sBody
            ))
            js_box = Table(
                [[Paragraph(f'<font size="7" fontName="Courier" color="{BRAND_MUTED.hexval()}">{preview}</font>', sBody)]],
                colWidths=[CONTENT_W]
            )
            js_box.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), BRAND_SURFACE),
                ("BOX",           (0, 0), (-1, -1), 1.5, BRAND_RED),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            story.append(js_box)
            story.append(Spacer(1, 6))

        story.append(Spacer(1, 8))

    # ────────────────────────────────────────
    # FOOTER
    # ────────────────────────────────────────
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_BORDER, spaceBefore=4, spaceAfter=6))
    story.append(ColorBar(height=4, color=BRAND_GOLD, gold_strip=False))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f'Generated by <b>TrustPDF</b> on {now_str}  •  '
        'This report is auto-generated. Review all findings with a qualified security professional.',
        sNote
    ))

    # ────────────────────────────────────────
    # Page canvas decorator (page numbers + dark background)
    # ────────────────────────────────────────
    def on_page(canvas, doc):
        canvas.saveState()
        # White page background
        canvas.setFillColor(WHITE)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # Gov-blue-dark top strip on every page (except first — first has ColorBar flowable)
        if doc.page > 1:
            canvas.setFillColor(BRAND_BLUE_DARK)
            canvas.rect(0, PAGE_H - 10 * mm, PAGE_W, 10 * mm, fill=1, stroke=0)
            canvas.setFillColor(BRAND_GOLD)
            canvas.rect(0, PAGE_H - 10 * mm, PAGE_W, 2, fill=1, stroke=0)
        # Page number bar at bottom
        canvas.setFillColor(BRAND_SURFACE)
        canvas.rect(0, 0, PAGE_W, 10 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(BRAND_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0, 10 * mm, PAGE_W, 10 * mm)
        canvas.setFillColor(BRAND_MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W - MARGIN, 3.5 * mm,
                               f"Page {doc.page}  |  TrustPDF Document Security Verification Service")
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def format_bytes(b: int) -> str:
    if b < 1024:       return f"{b} B"
    if b < 1024**2:    return f"{b/1024:.1f} KB"
    return f"{b/(1024**2):.1f} MB"


def format_enhanced_results_for_frontend(
    results: Dict[Any, Any], filename: str, file_size: int
) -> Dict[str, Any]:
    overall_risk   = results.get("overall_risk_level", "Unknown")
    final_verdict  = results.get("final_verdict", {})
    failed_checks  = final_verdict.get("failed_checks", 0)

    if   failed_checks >= 4: risk_class, risk_desc = "risk-critical", "Multiple critical security issues detected"
    elif failed_checks >= 2: risk_class, risk_desc = "risk-medium",   "Some security concerns detected"
    else:                     risk_class, risk_desc = "risk-low",      "Document appears relatively safe"

    file_size_mb       = round(file_size / (1024 * 1024), 2)
    incremental_updates = results.get("incremental_updates", 0)
    if isinstance(incremental_updates, str): incremental_updates = 0
    embedded_files_count = len(results.get("embedded_files", []))
    javascript_count     = results.get("javascript_count", 0)

    comprehensive_meta = results.get("comprehensive_metadata", {})
    metadata_fields = {
        "format": "Document Format", "title": "Title", "author": "Author",
        "creator": "Creator Software", "producer": "Producer Software",
        "creation_date": "Creation Date", "modification_date": "Modification Date",
        "subject": "Subject", "keywords": "Keywords",
    }
    metadata_table = [
        {"key": label, "value": str(comprehensive_meta.get(field)) if comprehensive_meta.get(field) else "Not specified"}
        for field, label in metadata_fields.items()
    ]

    all_findings = []
    for flag      in results.get("red_flags",            []): all_findings.append({"type": "critical", "title": "Critical Security Flag",  "description": flag,      "icon": "alert-triangle"})
    for issue     in results.get("security_issues",      []): all_findings.append({"type": "error",    "title": "Security Issue",           "description": issue,     "icon": "alert-circle"})
    for indicator in results.get("tampering_indicators", []): all_findings.append({"type": "warning",  "title": "Tampering Indicator",      "description": indicator, "icon": "alert-circle"})
    for error     in results.get("analysis_errors",      []): all_findings.append({"type": "info",     "title": "Analysis Error",           "description": error,     "icon": "info"})

    embedded_files = [
        {"name": f["name"], "size": f["size"], "size_formatted": format_bytes(f["size"])}
        for f in results.get("embedded_files", [])
    ]
    javascript_payloads = [
        {"id": i, "size": len(p), "preview": p[:100] + ("..." if len(p) > 100 else "")}
        for i, p in enumerate(results.get("javascript_payloads", []), 1)
    ]

    console_lines = []
    for line in results.get("console_output", []):
        if   any(w in line for w in ["🚨","RED FLAG","CRITICAL"]): lv, cc = "critical", "text-red-300 font-semibold"
        elif any(w in line for w in ["❌","ERROR","FAILED"]):      lv, cc = "error",    "text-red-400"
        elif any(w in line for w in ["⚠️","WARNING","SUSPICIOUS"]): lv, cc = "warning",  "text-yellow-400"
        elif any(w in line for w in ["✅","SUCCESS","SAFE"]):      lv, cc = "success",  "text-green-400"
        elif any(w in line for w in ["ℹ️","INFO","ANALYSIS"]):     lv, cc = "info",     "text-blue-400"
        else:                                                        lv, cc = "status",   "text-gray-300"
        console_lines.append({"level": lv, "message": line, "color_class": cc})

    verdict_formatted = format_final_verdict(final_verdict, overall_risk)

    return {
        "file_info": {
            "name": filename, "size": file_size,
            "size_formatted": f"{file_size_mb} MB",
            "hash": results.get("file_hash_sha256", "N/A"),
        },
        "risk_assessment": {
            "level": overall_risk, "class": risk_class,
            "description": risk_desc, "failed_checks": failed_checks,
        },
        "quick_stats": {
            "incremental_updates": incremental_updates,
            "embedded_files":      embedded_files_count,
            "javascript_blocks":   javascript_count,
            "failed_security_checks": failed_checks,
        },
        "metadata": {"table": metadata_table, "has_metadata": bool(comprehensive_meta), "comprehensive": comprehensive_meta},
        "security_details": {
            "encryption": results.get("encryption", "Not analyzed"),
            "embedded_files": embedded_files,
            "javascript_payloads": javascript_payloads,
            "xref_total":   results.get("xref_total", 0),
            "image_count":  results.get("image_count", 0),
            "optimization_reduction": results.get("optimization_reduction", 0),
        },
        "findings": all_findings,
        "recommendations": results.get("recommendations", []),
        "console_output": console_lines,
        "final_verdict": verdict_formatted,
        "analysis_complete": True,
        "analysis_errors_count": len(results.get("analysis_errors", [])),
    }


def format_final_verdict(verdict_data: Dict[str, Any], overall_risk: str) -> Dict[str, Any]:
    if not verdict_data:
        return {
            "overall": "Analysis Incomplete", "explanation": "Unable to generate final verdict",
            "detailed_checks": [], "icon": "🔍", "css_class": "verdict-low",
            "summary": "No verdict available", "failed_checks": 0,
        }

    if   "HIGH RISK"   in overall_risk: icon, css = "🔴", "verdict-critical"
    elif "MEDIUM RISK" in overall_risk: icon, css = "🟡", "verdict-medium"
    else:                                icon, css = "🟢", "verdict-low"

    formatted_checks = []
    for check in verdict_data.get("detailed_checks", []):
        if   check.startswith("✅"): formatted_checks.append({"status": "pass",    "text": check[2:].strip(), "icon": "✅"})
        elif check.startswith("❌"): formatted_checks.append({"status": "fail",    "text": check[2:].strip(), "icon": "❌"})
        elif check.startswith("⚠️"): formatted_checks.append({"status": "warning", "text": check[2:].strip(), "icon": "⚠️"})
        else:                         formatted_checks.append({"status": "info",    "text": check,             "icon": "ℹ️"})

    failed_checks = verdict_data.get("failed_checks", 0)
    if   failed_checks >= 4: summary = f"Document failed {failed_checks}/8 security checks. High risk of tampering or malicious content."
    elif failed_checks >= 2: summary = f"Document failed {failed_checks}/8 security checks. Some security concerns detected."
    else:                     summary = f"Document passed most security checks ({8-failed_checks}/8). Appears trustworthy with normal security precautions."

    return {
        "overall": verdict_data.get("overall", "Unknown"),
        "explanation": verdict_data.get("explanation", "No explanation available"),
        "detailed_checks": formatted_checks,
        "icon": icon, "css_class": css, "summary": summary,
        "failed_checks": failed_checks, "total_checks": 8,
        "raw_checks": verdict_data.get("detailed_checks", []),
    }


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def read_root():
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>TrustPDF Enhanced</h1><p>Please ensure static/index.html exists</p>",
            status_code=200,
        )


@app.post("/analyze")
async def analyze_pdf(file: UploadFile = File(...)):
    """Analyze uploaded PDF file and return enhanced results with Final Verdict."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    content   = await file.read()
    file_size = len(content)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(content)
            temp_file_path = tmp.name

        detector  = PDFTamperingDetector(temp_file_path)
        results   = detector.analyze_pdf()
        formatted = format_enhanced_results_for_frontend(results, file.filename, file_size)
        return JSONResponse(content=formatted)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try: os.unlink(temp_file_path)
            except Exception: pass


@app.post("/report/pdf")
async def generate_report(file: UploadFile = File(...)):
    """
    Analyze a PDF and immediately return a downloadable PDF security report.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    content   = await file.read()
    file_size = len(content)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(content)
            temp_file_path = tmp.name

        detector      = PDFTamperingDetector(temp_file_path)
        results       = detector.analyze_pdf()
        analysis_data = format_enhanced_results_for_frontend(results, file.filename, file_size)
        pdf_bytes     = generate_pdf_report(analysis_data)

        safe_name = Path(file.filename).stem
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="TrustPDF_Report_{safe_name}.pdf"'},
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try: os.unlink(temp_file_path)
            except Exception: pass


@app.post("/report/pdf-from-json")
async def generate_report_from_json(analysis_data: Dict[str, Any]):
    """
    Accept pre-analyzed JSON data and return a PDF report.
    Use this endpoint when you already have analysis results from /analyze
    and just want to generate the report without re-analyzing.

    Example:
        # 1. Analyze
        result = POST /analyze  (with PDF file)
        # 2. Generate report
        report = POST /report/pdf-from-json  (with result JSON body)
    """
    try:
        pdf_bytes = generate_pdf_report(analysis_data)
        filename  = analysis_data.get("file_info", {}).get("name", "document")
        safe_name = Path(filename).stem
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="TrustPDF_Report_{safe_name}.pdf"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@app.post("/api/quick-check")
async def quick_check(file: UploadFile = File(...)):
    """Quick security check — returns only risk level and critical issues."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    content   = await file.read()
    file_size = len(content)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(content)
            temp_file_path = tmp.name

        detector      = PDFTamperingDetector(temp_file_path)
        results       = detector.analyze_pdf()
        final_verdict = results.get("final_verdict", {})
        return {
            "filename":       file.filename,
            "risk_level":     results.get("overall_risk_level", "Unknown"),
            "failed_checks":  final_verdict.get("failed_checks", 0),
            "total_checks":   8,
            "verdict":        final_verdict.get("overall", "Unknown"),
            "critical_issues":results.get("red_flags", [])[:3],
            "is_safe":        final_verdict.get("failed_checks", 0) < 2,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quick check failed: {str(e)}")
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try: os.unlink(temp_file_path)
            except Exception: pass


@app.get("/api/quick-check")
async def quick_check_info():
    return {
        "endpoint": "/api/quick-check", "method": "POST",
        "description": "Quick security check — returns only risk level and critical issues",
        "usage": "Send a POST request with a PDF file in the 'file' field",
        "example": "curl -X POST http://localhost:8000/api/quick-check -F 'file=@document.pdf'",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "TrustPDF Enhanced Security Scanner",
        "version": "2.0.0",
        "features": [
            "Comprehensive metadata validation",
            "Software whitelist verification",
            "Enhanced tampering detection",
            "User-friendly security verdicts",
            "8-point security checklist",
            "PDF report export (/report/pdf, /report/pdf-from-json)",  # NEW
        ],
    }


@app.get("/api/info")
async def get_api_info():
    return {
        "name": "TrustPDF Enhanced API",
        "version": "2.0.0",
        "description": "Advanced PDF security analysis with comprehensive tampering detection",
        "endpoints": {
            "/":                      "Main web interface",
            "/analyze":               "POST — Upload and analyze PDF file",
            "/report/pdf":            "POST — Analyze PDF and download PDF security report",   # NEW
            "/report/pdf-from-json":  "POST — Generate PDF report from existing JSON analysis", # NEW
            "/api/quick-check":       "POST — Fast risk-level check",
            "/health":                "GET  — Health check",
            "/api/info":              "GET  — API information",
        },
        "security_checks": [
            "1. Complete metadata validation (format, title, author, creator, producer, dates)",
            "2. Creation vs modification date consistency",
            "3. Incremental update detection (document modifications)",
            "4. Software whitelist verification with 85% similarity threshold",
            "5. JavaScript and executable code detection",
            "6. Encryption analysis",
            "7. Embedded files detection",
            "8. File structure integrity (orphaned objects within ±10%)",
        ],
        "risk_levels": {"LOW": "0-1 failed checks", "MEDIUM": "2-3 failed checks", "HIGH": "4+ failed checks"},
    }


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting TrustPDF Enhanced PDF Security Scanner")
    print("=" * 50)
    print("Server: http://localhost:8000/")
    print("Docs:   http://localhost:8000/docs")
    print("─" * 50)
    print("NEW  →  PDF Report: POST http://localhost:8000/report/pdf")
    print("NEW  →  From JSON:  POST http://localhost:8000/report/pdf-from-json")
    print("=" * 50)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")