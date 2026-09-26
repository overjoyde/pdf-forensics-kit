"""File-structure anomalies: prepended/appended data, repairs, unreachable objects, encryption."""

from __future__ import annotations

import re

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import MAX_DECODED_STREAM_BYTES, StreamTooLarge, _walk, get, name, read_stream, stream_fits

SKIP_TYPES = {"/ObjStm", "/XRef"}
_OBJ_AT = re.compile(rb"\s*(\d+)\s+(\d+)\s+obj")


_TEXT_OPS = re.compile(rb"\bBT\b.*?(Tj|TJ|')", re.S)


def _is_content_bearing(obj: pikepdf.Object, kind: str, oversize: list[pikepdf.Object] | None = None) -> bool:
    if kind in ("/Page", "/Annot") or "/Rect" in obj:
        return True
    if "/Length1" in obj or (kind in ("/Metadata", "/EmbeddedFile", "/XObject")
                             and name(get(obj, "/Subtype")) != "/Form"):
        return False  # font programs, XMP, attachments, images
    if isinstance(obj, pikepdf.Stream) and name(get(obj, "/Subtype")) in ("", "/Form"):
        try:
            data, truncated = read_stream(obj, 262144)
            if truncated and oversize is not None and not stream_fits(obj, MAX_DECODED_STREAM_BYTES):
                oversize.append(obj)
        except StreamTooLarge:
            if oversize is not None:
                oversize.append(obj)
            return False
        except Exception:
            return False
        return bool(_TEXT_OPS.search(data))
    return False


def _linearization_objects(doc: Document) -> set[tuple[int, int]]:
    """The linearization dictionary and hint stream are unreferenced by design."""
    out: set[tuple[int, int]] = set()
    if not doc.raw.linearized:
        return out
    head = doc.data[:1024]
    first = re.search(rb"(\d+)\s+(\d+)\s+obj\s*<<\s*/Linearized", head)
    if first:
        out.add((int(first.group(1)), int(first.group(2))))
    h = re.search(rb"/H\s*\[\s*(\d+)", head)
    if h:
        mm = _OBJ_AT.match(doc.data, int(h.group(1)))
        if mm:
            out.add((int(mm.group(1)), int(mm.group(2))))
    return out


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="structure")
    rs = doc.raw
    pdf = doc.pdf
    res.facts.update({
        "size": rs.size, "header_version": rs.header_version, "pdf_version": pdf.pdf_version,
        "header_offset": rs.header_offset, "linearized": rs.linearized, "xref_style": rs.xref_style,
        "xref_sections": len(rs.sections), "eof_markers": rs.eof_marker_count,
        "encrypted": pdf.is_encrypted, "pages": len(pdf.pages), "objects": len(pdf.objects),
        "open_warnings": doc.open_warnings[:30],
    })

    if rs.header_offset > 0:
        res.findings.append(Finding(
            id="structure.data-before-header", title=f"{rs.header_offset} byte(s) before the %PDF header",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="structure",
            explanation="Data before %PDF- is ignored by viewers. It can hide a second file format (polyglot).",
            evidence={"offset": rs.header_offset,
                      "preview": doc.data[:min(rs.header_offset, 64)].decode("latin-1", "replace")},
            benign_explanations=["Mail gateways or download wrappers adding a prefix"]))

    if rs.trailing_bytes:
        res.findings.append(Finding(
            id="structure.data-after-eof", title=f"{rs.trailing_bytes} byte(s) of data after the final %%EOF",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="structure",
            explanation=("Bytes after the last %%EOF are not part of any revision. They can carry an appended "
                         "file, a broken incremental update, or hidden data."),
            evidence={"bytes": rs.trailing_bytes, "preview": rs.trailing_preview},
            benign_explanations=["Scanner or upload software padding"]))

    expected_eofs = len(rs.revisions) + (1 if rs.linearized else 0)
    if rs.eof_marker_count > expected_eofs and not rs.chain_errors:
        res.findings.append(Finding(
            id="structure.extra-eof-markers",
            title=f"{rs.eof_marker_count - expected_eofs} %%EOF marker(s) not linked to any revision",
            severity=Severity.LOW, confidence=Confidence.LOW, category="structure",
            explanation=("There are more end-of-file markers than revisions in the cross-reference chain. Possible causes: "
                         "an embedded PDF attachment, an orphaned update, or two files concatenated."),
            evidence={"eof_markers": rs.eof_marker_count, "revisions": len(rs.revisions)},
            benign_explanations=["Embedded PDF attachment (check active-content findings)"]))

    if doc.open_warnings:
        res.findings.append(Finding(
            id="structure.repaired", title="The PDF needed repair when opened",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="structure",
            explanation=("qpdf reported structural errors and repaired them. Viewers repair these silently. Damage can "
                         "come from careless manual editing or from transfer corruption."),
            evidence={"warnings": doc.open_warnings[:20]},
            benign_explanations=["Buggy producer", "File truncated during upload/download"]))

    # unreachable objects in the current (latest) object table
    try:
        reachable = {o.objgen for o in _walk(pdf.trailer, limit=doc.options.max_objects * 4)}
        # /Parent and /P links are skipped by _walk; pages and annotations are reachable from the root anyway
        reachable |= _linearization_objects(doc)
        unreachable: list[str] = []
        content_bearing: list[str] = []
        oversize: list[pikepdf.Object] = []
        for obj in pdf.objects:
            if obj is None or not isinstance(obj, pikepdf.Object):
                continue
            if not obj.is_indirect or obj.objgen in reachable:
                continue
            if isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary)) and name(get(obj, "/Type")) in SKIP_TYPES:
                continue
            if not isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary)):
                continue  # indirect numbers/arrays (e.g. /Length values) carry no content
            if isinstance(obj, pikepdf.Dictionary) and len(obj.keys()) == 0:
                continue
            kind = (name(get(obj, "/Type")) or name(get(obj, "/Subtype"))
                    or ("stream" if isinstance(obj, pikepdf.Stream) else "dictionary"))
            label = f"{obj.objgen[0]} {obj.objgen[1]} R ({kind})"
            unreachable.append(label)
            if _is_content_bearing(obj, kind, oversize):
                content_bearing.append(label)
        res.facts["unreachable_objects"] = len(unreachable)
        if unreachable:
            res.findings.append(Finding(
                id="structure.unreachable-objects",
                title=(f"{len(content_bearing)} unreferenced object(s) that carry page content"
                       if content_bearing else f"{len(unreachable)} unreferenced object(s)"),
                severity=Severity.LOW if content_bearing else Severity.INFO,
                confidence=Confidence.MEDIUM, category="structure",
                explanation=("Objects in the cross-reference table that nothing points to. Unused fonts and resources "
                             "are common. Leftover pages, annotations or text-drawing streams can be remnants of "
                             "removed content. Inspect them with 'qpdf --show-object=N --filtered-stream-data'."),
                evidence={"content_bearing": content_bearing[:30], "objects": unreachable[:30]},
                benign_explanations=["Many generators leave unused fonts/resources behind"]))
        if oversize:
            res.findings.append(Finding(
                id="analysis.stream-too-large",
                title=f"{len(oversize)} unreferenced stream(s) decode to more than "
                      f"{MAX_DECODED_STREAM_BYTES // (1024 * 1024)} MB",
                severity=Severity.LOW, confidence=Confidence.HIGH, category="structure",
                explanation=("These streams were only sampled, not decoded in full. An unreferenced stream that "
                             "expands this much is a decompression-bomb pattern."),
                evidence={"objects": [f"{o.objgen[0]} {o.objgen[1]} R" for o in oversize[:30]],
                          "limit_bytes": MAX_DECODED_STREAM_BYTES},
                benign_explanations=["Leftover large image or font data from an earlier save"]))
    except Exception as exc:
        res.facts["unreachable_error"] = str(exc)

    if pdf.is_encrypted:
        try:
            enc = pdf.encryption
            ev = {"R": enc.R, "V": enc.V, "stream_method": str(enc.stream_method), "bits": enc.bits}
        except Exception:
            ev = {}
        res.findings.append(Finding(
            id="structure.encrypted", title="Document is encrypted", severity=Severity.INFO,
            confidence=Confidence.HIGH, category="structure",
            explanation=("Encryption with only an owner password restricts editing but not reading. Structural "
                         "analysis still works."),
            evidence=ev))
    return res
