"""Metadata consistency: Info dictionary vs XMP, date logic, producer chain, XMP edit history."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import date_diff, get, iso, parse_pdf_date, parse_xmp_date, s

MAX_XMP_BYTES = 2 * 1024 * 1024
EXACT_TOLERANCE = timedelta(minutes=2)
NAIVE_TOLERANCE = timedelta(hours=14)  # max UTC offset spread when a timezone is missing

# Online editors / consumer "edit any PDF" tools. Their presence is not proof of fraud (people
# compress and merge files with them) but documents from an issuing system should not carry them.
EDITOR_TOOLS = {
    "ilovepdf": "iLovePDF (online)", "smallpdf": "Smallpdf (online)", "sejda": "Sejda (online/desktop editor)",
    "pdf24": "PDF24", "sodapdf": "Soda PDF", "soda pdf": "Soda PDF", "pdfcandy": "PDF Candy (online)",
    "pdf2go": "PDF2Go (online)", "online2pdf": "Online2PDF", "pdfescape": "PDFescape (online editor)",
    "pdffiller": "pdfFiller (online editor)", "dochub": "DocHub (online editor)",
    "pdf-xchange editor": "PDF-XChange Editor", "foxit phantompdf": "Foxit PhantomPDF",
    "foxit pdf editor": "Foxit PDF Editor", "nitro pro": "Nitro Pro", "wondershare": "Wondershare PDFelement",
    "pdfelement": "Wondershare PDFelement", "icecream pdf": "Icecream PDF Editor", "canva": "Canva",
}
MANIPULATION_TOOLS = {
    "qpdf": "QPDF", "pdftk": "PDFtk", "ghostscript": "Ghostscript", "gpl ghostscript": "Ghostscript",
    "mutool": "MuPDF mutool", "cpdf": "Coherent PDF", "pypdf": "pypdf", "pikepdf": "pikepdf",
}

NS = {
    "x": "adobe:ns:meta/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "pdf": "http://ns.adobe.com/pdf/1.3/",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "dc": "http://purl.org/dc/elements/1.1/",
}


def _xmp_value(root: ET.Element, prefix: str, local: str) -> str | None:
    tag = f"{{{NS[prefix]}}}{local}"
    for desc in root.iter(f"{{{NS['rdf']}}}Description"):
        attr = desc.get(tag)
        if attr:
            return attr.strip()
        el = desc.find(tag)
        if el is not None:
            if el.text and el.text.strip():
                return el.text.strip()
            li = el.find(f".//{{{NS['rdf']}}}li")
            if li is not None and li.text:
                return li.text.strip()
    return None


def _xmp_history(root: ET.Element) -> list[dict[str, str]]:
    out = []
    for hist in root.iter(f"{{{NS['xmpMM']}}}History"):
        for li in hist.iter(f"{{{NS['rdf']}}}li"):
            ev = {}
            for key in ("action", "when", "softwareAgent", "changed", "instanceID"):
                tag = f"{{{NS['stEvt']}}}{key}"
                v = li.get(tag)
                if v is None:
                    el = li.find(tag)
                    v = el.text if el is not None else None
                if v:
                    ev[key] = v.strip()
            if ev:
                out.append(ev)
    return out[:100]


def read_xmp(pdf: pikepdf.Pdf) -> tuple[dict[str, Any] | None, str | None]:
    md = get(pdf.Root, "/Metadata")
    if not isinstance(md, pikepdf.Stream):
        return None, None
    try:
        raw = md.read_bytes()
    except Exception as exc:
        return None, f"XMP stream unreadable: {exc}"
    if len(raw) > MAX_XMP_BYTES:
        return None, "XMP stream larger than 2 MB; skipped"
    text = raw.decode("utf-8", errors="replace")
    # XMP packets may carry a BOM / xpacket PI; ET handles PIs, strip leading junk.
    start = text.find("<")
    if start == -1:
        return None, "XMP stream is not XML"
    if "<!ENTITY" in text:
        return None, "XMP contains entity declarations; not parsed (safety)"
    try:
        root = ET.fromstring(text[start:].rsplit(">", 1)[0] + ">")
    except ET.ParseError as exc:
        return None, f"XMP is not well-formed: {exc}"
    return {
        "create_date": _xmp_value(root, "xmp", "CreateDate"),
        "modify_date": _xmp_value(root, "xmp", "ModifyDate"),
        "metadata_date": _xmp_value(root, "xmp", "MetadataDate"),
        "creator_tool": _xmp_value(root, "xmp", "CreatorTool"),
        "producer": _xmp_value(root, "pdf", "Producer"),
        "document_id": _xmp_value(root, "xmpMM", "DocumentID"),
        "instance_id": _xmp_value(root, "xmpMM", "InstanceID"),
        "title": _xmp_value(root, "dc", "title"),
        "history": _xmp_history(root),
    }, None


def _tool_hits(values: list[str], table: dict[str, str]) -> list[str]:
    hits = []
    for v in values:
        low = v.lower()
        for key, label in table.items():
            if key in low and label not in hits:
                hits.append(label)
    return hits


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="metadata")
    pdf = doc.pdf
    info: dict[str, str] = {}
    try:
        for k, v in pdf.docinfo.items():
            info[str(k).lstrip("/")] = s(v)
    except Exception:
        pass
    xmp, xmp_err = read_xmp(pdf)

    trailer_id = get(pdf.trailer, "/ID")
    ids = []
    if isinstance(trailer_id, pikepdf.Array):
        for x in trailer_id:
            try:
                ids.append(bytes(x).hex())
            except Exception:
                pass

    res.facts.update({"info": info, "xmp": xmp, "trailer_id": ids,
                      "trailer_id_parts_equal": len(ids) == 2 and ids[0] == ids[1]})
    if xmp_err:
        res.facts["xmp_error"] = xmp_err

    now = datetime.now(timezone.utc)
    c_info = parse_pdf_date(info.get("CreationDate", ""))
    m_info = parse_pdf_date(info.get("ModDate", ""))
    c_xmp = parse_xmp_date(xmp["create_date"]) if xmp and xmp.get("create_date") else None
    m_xmp = parse_xmp_date(xmp["modify_date"]) if xmp and xmp.get("modify_date") else None
    res.facts["parsed_dates"] = {"info_creation": iso(c_info), "info_mod": iso(m_info),
                                 "xmp_create": iso(c_xmp), "xmp_modify": iso(m_xmp)}

    if not info and not xmp:
        res.findings.append(Finding(
            id="metadata.absent", title="No document metadata", severity=Severity.INFO,
            confidence=Confidence.HIGH, category="metadata",
            explanation="Neither an Info dictionary nor XMP metadata is present.",
            benign_explanations=["Some generators and privacy tools strip metadata"]))

    # modification before creation
    for label, c, m in (("Info", c_info, m_info), ("XMP", c_xmp, m_xmp)):
        if c and m:
            delta, exact = date_diff(m, c)
            tol = EXACT_TOLERANCE if exact else NAIVE_TOLERANCE
            if delta < -tol:
                res.findings.append(Finding(
                    id="metadata.modified-before-created",
                    title=f"{label} modification date is earlier than the creation date",
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH if exact else Confidence.MEDIUM,
                    category="metadata",
                    explanation="A document cannot be modified before it was created. The dates were set by hand, by a "
                                "tool that copies them wrongly, or on a machine with a wrong clock.",
                    evidence={"created": iso(c), "modified": iso(m), "difference": str(delta),
                              "timezone_exact": exact},
                    benign_explanations=["Wrong system clock on the producing machine",
                                         "Template whose creation date was carried over"]))

    # future dates
    for label, d in (("Info CreationDate", c_info), ("Info ModDate", m_info),
                     ("XMP CreateDate", c_xmp), ("XMP ModifyDate", m_xmp)):
        if d:
            dd = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            if dd - now > timedelta(days=1):
                res.findings.append(Finding(
                    id="metadata.future-date", title=f"{label} lies in the future",
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="metadata",
                    explanation="A timestamp later than the time of analysis points to a manually set date or a wrong clock.",
                    evidence={"field": label, "value": iso(d), "analysed_at": now.isoformat()}))

    # Info vs XMP
    for label, a, b in (("creation", c_info, c_xmp), ("modification", m_info, m_xmp)):
        if a and b:
            delta, exact = date_diff(a, b)
            tol = EXACT_TOLERANCE if exact else NAIVE_TOLERANCE
            if abs(delta) > tol:
                res.findings.append(Finding(
                    id="metadata.info-xmp-date-mismatch",
                    title=f"Info and XMP {label} dates disagree",
                    severity=Severity.LOW, confidence=Confidence.MEDIUM if exact else Confidence.LOW,
                    category="metadata",
                    explanation=("PDFs store dates twice. Tools that edit a file often update only one of them, "
                                 "so a disagreement shows the file was processed by a second tool."),
                    evidence={"info": iso(a), "xmp": iso(b), "difference": str(delta), "timezone_exact": exact},
                    benign_explanations=["Metadata updated by a document management system"]))

    info_prod = info.get("Producer", "")
    xmp_prod = (xmp or {}).get("producer") or ""
    if info_prod and xmp_prod and _norm(info_prod) != _norm(xmp_prod):
        res.findings.append(Finding(
            id="metadata.producer-mismatch", title="Info and XMP disagree on the producing software",
            severity=Severity.LOW, confidence=Confidence.MEDIUM, category="metadata",
            explanation="Different producers in the two metadata stores mean a second program re-wrote the file.",
            evidence={"info_producer": info_prod, "xmp_producer": xmp_prod}))

    tool_fields = [info.get("Producer", ""), info.get("Creator", ""),
                   (xmp or {}).get("creator_tool") or "", xmp_prod]
    tool_fields += [e.get("softwareAgent", "") for e in (xmp or {}).get("history", [])]
    tool_fields = [t for t in tool_fields if t]
    editors = _tool_hits(tool_fields, EDITOR_TOOLS)
    if editors:
        res.findings.append(Finding(
            id="metadata.editor-tool", title="Processed with a general-purpose PDF editor",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="metadata",
            explanation=("Metadata names a consumer or online PDF editor. Documents issued directly by a bank, "
                         "insurer or ERP system are not expected to pass through such tools."),
            evidence={"tools": editors, "metadata_fields": tool_fields},
            benign_explanations=["The recipient compressed, merged or split the file", "Editor used to add a signature image"]))
    manip = _tool_hits(tool_fields, MANIPULATION_TOOLS)
    if manip:
        res.findings.append(Finding(
            id="metadata.manipulation-library", title="Re-written by a PDF manipulation library",
            severity=Severity.INFO, confidence=Confidence.HIGH, category="metadata",
            explanation="The file was re-written by a PDF manipulation library. This is common in automated pipelines.",
            evidence={"tools": manip}))

    history = (xmp or {}).get("history") or []
    agents = sorted({e.get("softwareAgent", "") for e in history if e.get("softwareAgent")})
    if history:
        res.findings.append(Finding(
            id="metadata.xmp-history", title=f"XMP edit history has {len(history)} event(s)",
            severity=Severity.LOW if len(agents) > 1 else Severity.INFO,
            confidence=Confidence.MEDIUM, category="metadata",
            explanation="The XMP history records save/convert events and the software that performed them.",
            evidence={"events": history[:30], "software_agents": agents}))
    return res


def _norm(v: str) -> str:
    return re.sub(r"[\d.\s®™()\-_,;:]+", "", v.lower())
