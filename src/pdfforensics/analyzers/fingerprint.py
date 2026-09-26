"""Source fingerprint: characteristics of the software pipeline that produced the file.

Documents from the same issuing system usually share producer, PDF version, xref style,
object-stream use, filters and font set. Comparing fingerprints across a batch shows
documents that claim the same origin but were built differently.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult
from pdfforensics.pdfutil import get, name, s

KNOWN_PRODUCERS = {
    "pdfsharp": "PDFsharp (.NET)", "itext": "iText", "openpdf": "OpenPDF", "reportlab": "ReportLab",
    "fpdf": "FPDF", "tcpdf": "TCPDF", "wkhtmltopdf": "wkhtmltopdf", "weasyprint": "WeasyPrint",
    "skia": "Chrome/Skia", "chromium": "Chrome/Skia", "headlesschrome": "Chrome/Skia",
    "prince": "Prince", "adobe experience manager": "Adobe AEM Forms", "livecycle": "Adobe LiveCycle",
    "acrobat distiller": "Adobe Distiller", "adobe pdf library": "Adobe PDF Library", "acrobat": "Adobe Acrobat",
    "microsoft: print to pdf": "Microsoft Print to PDF", "microsoft": "Microsoft Office",
    "libreoffice": "LibreOffice", "openoffice": "OpenOffice", "quartz": "macOS Quartz", "cairo": "Cairo",
    "ghostscript": "Ghostscript", "qpdf": "QPDF", "pdftk": "PDFtk", "pdfium": "PDFium", "aspose": "Aspose",
    "pdfbox": "Apache PDFBox", "jasperreports": "JasperReports", "crystal reports": "Crystal Reports",
    "sap": "SAP", "abbyy": "ABBYY FineReader", "tesseract": "Tesseract OCR", "ocrmypdf": "OCRmyPDF",
}


def normalize_software(value: str) -> str:
    v = value.lower()
    v = re.sub(r"\(.*?\)", " ", v)
    v = re.sub(r"\b(v(ersion)?\s*)?\d+([.\-_]\d+)*\w*\b", " ", v)
    return re.sub(r"[\s;,:®™]+", " ", v).strip()


def classify(value: str) -> str | None:
    low = value.lower()
    for key, label in KNOWN_PRODUCERS.items():
        if key in low:
            return label
    return None


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="fingerprint")
    pdf = doc.pdf
    info = {}
    try:
        info = {str(k).lstrip("/"): s(v) for k, v in pdf.docinfo.items()}
    except Exception:
        pass
    producer, creator = info.get("Producer", ""), info.get("Creator", "")

    filters: Counter = Counter()
    fonts: set[str] = set()
    has_objstm = False
    for i, obj in enumerate(pdf.objects):
        if i >= doc.options.max_objects:
            break
        try:
            if isinstance(obj, pikepdf.Stream):
                if name(get(obj, "/Type")) == "/ObjStm":
                    has_objstm = True
                f = get(obj, "/Filter")
                if isinstance(f, pikepdf.Array):
                    filters.update(str(x) for x in f)
                elif f is not None:
                    filters[str(f)] += 1
            elif isinstance(obj, pikepdf.Dictionary) and name(get(obj, "/Type")) == "/Font":
                base = name(get(obj, "/BaseFont")).lstrip("/")
                if base:
                    fonts.add(re.sub(r"^[A-Z]{6}\+", "", base))
        except Exception:
            continue

    sizes = Counter()
    for i, page in enumerate(pdf.pages):
        if i >= 50:
            break
        try:
            mb = [round(float(x)) for x in page.mediabox]
            sizes[f"{mb[2] - mb[0]}x{mb[3] - mb[1]}"] += 1
        except Exception:
            pass

    fp = {
        "producer": producer, "creator": creator,
        "producer_normalized": normalize_software(producer),
        "creator_normalized": normalize_software(creator),
        "producer_family": classify(producer) or classify(creator),
        "pdf_version": pdf.pdf_version,
        "xref_style": doc.raw.xref_style,
        "object_streams": has_objstm,
        "linearized": doc.raw.linearized,
        "filters": sorted(filters),
        "fonts": sorted(fonts)[:100],
        "page_sizes": dict(sizes),
    }
    stable = "|".join([fp["producer_normalized"], fp["creator_normalized"], fp["pdf_version"],
                       fp["xref_style"], str(has_objstm), ",".join(fp["filters"])])
    fp["pipeline_hash"] = hashlib.sha256(stable.encode()).hexdigest()[:16]
    res.facts.update(fp)
    return res


def similarity(a: dict, b: dict) -> float:
    """0-100 similarity between two fingerprint fact dicts (documented weights)."""
    score = 0.0
    score += 25 if a["producer_normalized"] == b["producer_normalized"] else 0
    score += 15 if a["creator_normalized"] == b["creator_normalized"] else 0
    score += 10 if a["pdf_version"] == b["pdf_version"] else 0
    score += 10 if a["xref_style"] == b["xref_style"] else 0
    score += 10 if a["object_streams"] == b["object_streams"] else 0
    score += 10 if a["filters"] == b["filters"] else 0
    fa, fb = set(a["fonts"]), set(b["fonts"])
    score += 20 * (len(fa & fb) / len(fa | fb)) if (fa or fb) else 20
    return round(score, 1)
