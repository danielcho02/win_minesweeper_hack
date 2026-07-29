import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
)


ROOT = Path(__file__).resolve().parents[1]
REPORT_MD = ROOT / "docs" / "analysis-report.md"
SCREENSHOT = ROOT / "analysis" / "winmine_verification.png"
OUTPUT_DIR = ROOT / "output" / "pdf"
OUTPUT_PDF = OUTPUT_DIR / "WinMine_지뢰찾기_분석_보고서.pdf"


def register_fonts():
    font_dir = Path("C:/Windows/Fonts")
    regular = font_dir / "malgun.ttf"
    bold = font_dir / "malgunbd.ttf"
    pdfmetrics.registerFont(TTFont("Malgun", str(regular)))
    pdfmetrics.registerFont(TTFont("Malgun-Bold", str(bold)))


def build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontName="Malgun-Bold",
            fontSize=20,
            leading=28,
            alignment=TA_CENTER,
            spaceAfter=10 * mm,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Malgun-Bold",
            fontSize=14,
            leading=19,
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
        ),
        "h3": ParagraphStyle(
            "H3",
            parent=base["Heading3"],
            fontName="Malgun-Bold",
            fontSize=11.5,
            leading=16,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Malgun",
            fontSize=9.3,
            leading=14,
            alignment=TA_LEFT,
            spaceAfter=1.8 * mm,
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base["BodyText"],
            fontName="Malgun",
            fontSize=9,
            leading=13,
            leftIndent=6 * mm,
            firstLineIndent=-3 * mm,
            spaceAfter=1.1 * mm,
        ),
        "code": ParagraphStyle(
            "Code",
            parent=base["Code"],
            fontName="Courier",
            fontSize=7.6,
            leading=10,
            leftIndent=4 * mm,
            rightIndent=4 * mm,
            backColor=colors.HexColor("#F4F6F8"),
            borderColor=colors.HexColor("#DDE3EA"),
            borderWidth=0.5,
            borderPadding=4,
            spaceBefore=1.5 * mm,
            spaceAfter=2.5 * mm,
        ),
        "caption": ParagraphStyle(
            "Caption",
            parent=base["BodyText"],
            fontName="Malgun",
            fontSize=8,
            leading=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#555555"),
            spaceBefore=1 * mm,
            spaceAfter=3 * mm,
        ),
    }


def inline_markup(text):
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", text)
    return text


def add_paragraph(story, text, style):
    if text.strip():
        story.append(Paragraph(inline_markup(text.strip()), style))


def image_flowable(path):
    from PIL import Image as PILImage

    rgb_path = ROOT / "tmp" / "pdfs" / "winmine_verification_rgb.png"
    rgb_path.parent.mkdir(parents=True, exist_ok=True)
    with PILImage.open(path) as source:
        source.convert("RGB").save(rgb_path)
    img = Image(str(rgb_path))
    max_width = 120 * mm
    max_height = 140 * mm
    scale = min(max_width / img.imageWidth, max_height / img.imageHeight, 1)
    img.drawWidth = img.imageWidth * scale
    img.drawHeight = img.imageHeight * scale
    return img


def build_story(markdown, styles):
    story = []
    in_code = False
    code_lines = []

    for raw in markdown.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_lines), styles["code"]))
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            story.append(Spacer(1, 1.2 * mm))
            continue

        if line.startswith("# "):
            story.append(Paragraph(inline_markup(line[2:]), styles["title"]))
        elif line.startswith("## "):
            story.append(Paragraph(inline_markup(line[3:]), styles["h2"]))
        elif line.startswith("### "):
            story.append(Paragraph(inline_markup(line[4:]), styles["h3"]))
        elif line.startswith("- "):
            story.append(Paragraph("- " + inline_markup(line[2:]), styles["bullet"]))
        elif re.match(r"^\d+\.\s", line):
            story.append(Paragraph(inline_markup(line), styles["bullet"]))
        elif line.startswith("![") and SCREENSHOT.exists():
            story.append(image_flowable(SCREENSHOT))
            story.append(Paragraph("동적 검증 후 승리 상태 스크린샷", styles["caption"]))
        else:
            add_paragraph(story, line, styles["body"])

    if in_code and code_lines:
        story.append(Preformatted("\n".join(code_lines), styles["code"]))
    return story


def page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Malgun", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawRightString(200 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def main():
    register_fonts()
    styles = build_styles()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    markdown = REPORT_MD.read_text(encoding="utf-8")
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    doc.build(build_story(markdown, styles), onFirstPage=page_number, onLaterPages=page_number)
    print(OUTPUT_PDF)


if __name__ == "__main__":
    main()
