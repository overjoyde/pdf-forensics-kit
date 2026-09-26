"""Incremental-update analysis: what changed in each revision, and how the visible text changed.

Each revision ``data[:end]`` is itself a complete PDF, so earlier versions of the document
(and earlier versions of every superseded object) can be recovered and compared.
"""

from __future__ import annotations

import difflib
import io
import logging
from collections import Counter
from typing import Any

import pikepdf

from pdfforensics.document import Document, open_bytes
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import object_digest, role_map

logging.getLogger("pypdf").setLevel(logging.ERROR)

CONTENT_ROLES = {"content", "resource", "page"}
BENIGN_UPDATE_ROLES = {"dss", "metadata", "info", "catalog", "signature", "structure"}
MAX_DIFF_LINES = 200


def _page_core_digest(obj: pikepdf.Object) -> str | None:
    """Digest of a page dictionary ignoring /Annots.

    Adding a comment, form widget or signature field changes the page's /Annots array.
    That is an annotation-level change, not a change to what the page itself draws.
    """
    try:
        if isinstance(obj, pikepdf.Dictionary) and obj.get("/Type") == pikepdf.Name.Page:
            items = sorted((str(k), v.unparse(resolved=False) if hasattr(v, "unparse") else repr(v))
                           for k, v in obj.items() if k != "/Annots")
            return repr(items)
    except Exception:
        return None
    return None


def _snapshot(pdf: pikepdf.Pdf, limit: int) -> tuple[dict[tuple[int, int], str], dict, bool]:
    digests: dict[tuple[int, int], str] = {}
    page_core: dict[tuple[int, int], str | None] = {}
    truncated = False
    for i, obj in enumerate(pdf.objects):
        if i >= limit:
            truncated = True
            break
        try:
            if obj.is_indirect:
                digests[obj.objgen] = object_digest(obj)
                core = _page_core_digest(obj)
                if core is not None:
                    page_core[obj.objgen] = core
        except Exception:
            continue
    return digests, page_core, truncated


def extract_text_by_page(data: bytes, max_pages: int) -> list[str]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data), strict=False)
    pages = []
    for i, page in enumerate(reader.pages):
        if i >= max_pages:
            break
        try:
            pages.append(page.extract_text() or "")
        except Exception:
            pages.append("")
    return pages


def text_diff(old_pages: list[str], new_pages: list[str]) -> dict[str, Any]:
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for pno in range(max(len(old_pages), len(new_pages))):
        a = old_pages[pno].splitlines() if pno < len(old_pages) else []
        b = new_pages[pno].splitlines() if pno < len(new_pages) else []
        if a == b:
            continue
        for line in difflib.unified_diff(a, b, lineterm="", n=0):
            if line.startswith(("+++", "---", "@@")):
                continue
            text = line[1:].strip()
            if not text:
                continue
            entry = {"page": pno + 1, "text": text[:300]}
            (added if line.startswith("+") else removed).append(entry)
    return {
        "page_count_before": len(old_pages),
        "page_count_after": len(new_pages),
        "added": added[:MAX_DIFF_LINES],
        "removed": removed[:MAX_DIFF_LINES],
        "truncated": len(added) > MAX_DIFF_LINES or len(removed) > MAX_DIFF_LINES,
    }


def signature_ends(doc: Document) -> list[int]:
    """Byte offsets where signed ranges end (c + d of each /ByteRange)."""
    ends = []
    for obj in doc.pdf.objects:
        try:
            if isinstance(obj, pikepdf.Dictionary) and "/ByteRange" in obj:
                br = [int(x) for x in obj["/ByteRange"]]
                if len(br) == 4:
                    ends.append(br[2] + br[3])
        except Exception:
            continue
    return sorted(set(ends))


def _matches_end(rev_end: int, sig_end: int, data: bytes) -> bool:
    if rev_end == sig_end:
        return True
    lo, hi = sorted((rev_end, sig_end))
    return hi - lo <= 4 and data[lo:hi].strip(b" \r\n\x00") == b""


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="revisions")
    rs = doc.raw
    revisions = rs.revisions
    res.facts.update({
        "revision_count": len(revisions),
        "incremental_updates": rs.update_count,
        "linearized": rs.linearized,
        "xref_style": rs.xref_style,
        "eof_markers": rs.eof_marker_count,
        "revision_ends": [r.end for r in revisions],
    })
    if rs.chain_errors:
        res.findings.append(Finding(
            id="structure.xref-chain-broken",
            title="Cross-reference chain could not be followed completely",
            severity=Severity.LOW, confidence=Confidence.MEDIUM, category="structure",
            explanation=("The startxref/Prev chain that links revisions is broken or points to the wrong "
                         "place. Revision history may be incomplete. Readers repair this silently."),
            evidence={"errors": rs.chain_errors},
            benign_explanations=["Buggy producer or file concatenation/truncation during transfer"],
        ))
    recovered = rs.recovered_revisions
    res.facts["recovered_revisions"] = [r.index for r in recovered]
    if recovered:
        res.findings.append(Finding(
            id="structure.unlinked-revision",
            title=f"{len(recovered)} earlier version(s) of the file not linked by the cross-reference chain",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="structure",
            explanation=("The file contains a complete earlier version that the startxref/Prev chain does not "
                         "lead to. Readers show only the latest version, so the earlier one is invisible in a "
                         "viewer. It has been recovered and compared like any other revision."),
            evidence={"revisions": [{"revision": r.index, "end": r.end} for r in recovered],
                      "chain_errors": rs.chain_errors},
            benign_explanations=["Producer that writes updates without /Prev",
                                 "Two PDF files concatenated during transfer"],
        ))
    if len(revisions) <= 1:
        return res

    sig_ends = signature_ends(doc)
    to_analyse = revisions[-doc.options.max_revisions:]
    if len(to_analyse) < len(revisions):
        res.facts["revisions_skipped"] = len(revisions) - len(to_analyse)

    prev_digests: dict[tuple[int, int], str] | None = None
    prev_text: list[str] | None = None
    updates: list[dict[str, Any]] = []
    updates_prev_end = 0
    prev_page_core: dict = {}

    for rev in to_analyse:
        chunk = doc.data[:rev.end]
        try:
            pdf, warns = open_bytes(chunk, doc.options.password)
        except Exception as exc:
            updates.append({"revision": rev.index, "end": rev.end, "error": f"cannot open: {exc}"})
            prev_digests, prev_text = None, None
            continue
        try:
            digests, page_core, truncated = _snapshot(pdf, doc.options.max_objects)
            try:
                text = extract_text_by_page(chunk, doc.options.max_pages)
            except Exception as exc:
                text = None
                res.facts.setdefault("text_errors", []).append(f"revision {rev.index}: {exc}")
            if prev_digests is not None:
                added = [og for og in digests if og not in prev_digests]
                removed = [og for og in prev_digests if og not in digests]
                changed = [og for og in digests if og in prev_digests and digests[og] != prev_digests[og]]
                roles = role_map(pdf)

                def role_of(og: tuple[int, int]) -> str:
                    r = roles.get(og, "other")
                    if r == "page" and og in page_core and prev_page_core.get(og) == page_core[og]:
                        return "annotation"  # only /Annots changed on this page
                    return r

                role_counts = Counter(role_of(og) for og in added + changed)
                is_sig = any(_matches_end(rev.end, e, doc.data) for e in sig_ends)
                entry: dict[str, Any] = {
                    "revision": rev.index,
                    "end": rev.end,
                    "bytes_added": rev.end - updates_prev_end,
                    "objects_added": len(added),
                    "objects_changed": len(changed),
                    "objects_removed": len(removed),
                    "changed_roles": dict(role_counts),
                    "changed_objects": [f"{o[0]} {o[1]} R" for o in (added + changed)[:50]],
                    "signing_revision": is_sig,
                    "open_warnings": warns[:10],
                    "objects_truncated": truncated,
                }
                if text is not None and prev_text is not None:
                    entry["text_diff"] = text_diff(prev_text, text)
                updates.append(entry)
            updates_prev_end = rev.end
            prev_digests, prev_text, prev_page_core = digests, text, page_core
        finally:
            pdf.close()

    res.facts["updates"] = updates
    last_sig_end = max(sig_ends) if sig_ends else None

    for u in updates:
        if "error" in u:
            res.findings.append(Finding(
                id="revisions.unreadable-revision", title=f"Revision {u['revision']} could not be opened",
                severity=Severity.LOW, confidence=Confidence.MEDIUM, category="revisions",
                explanation="An earlier version of the file could not be reconstructed.",
                evidence=u))
            continue
        roles = set(u["changed_roles"])
        diff = u.get("text_diff") or {}
        text_changed = bool(diff.get("added") or diff.get("removed"))
        evidence = {k: u[k] for k in ("revision", "bytes_added", "objects_added", "objects_changed",
                                      "objects_removed", "changed_roles", "changed_objects")}
        if text_changed:
            evidence["text_added"] = diff["added"][:20]
            evidence["text_removed"] = diff["removed"][:20]
        after_signature = last_sig_end is not None and u["end"] > last_sig_end + 4

        if u["signing_revision"] and not text_changed and roles <= (BENIGN_UPDATE_ROLES | {"annotation", "form", "other"}):
            res.findings.append(Finding(
                id="revisions.signature-update", title=f"Revision {u['revision']} adds a digital signature",
                severity=Severity.INFO, confidence=Confidence.HIGH, category="revisions",
                explanation="Signing a PDF always appends an incremental update. On its own this is not a modification.",
                evidence=evidence))
        elif roles and roles <= BENIGN_UPDATE_ROLES and not text_changed:
            res.findings.append(Finding(
                id="revisions.metadata-update",
                title=f"Revision {u['revision']} only changes metadata / validation data",
                severity=Severity.INFO if not after_signature else Severity.LOW,
                confidence=Confidence.MEDIUM, category="revisions",
                explanation=("The update touches only metadata, the catalog or long-term-validation data "
                             "(DSS), not page content."),
                evidence=evidence,
                benign_explanations=["LTV enrichment after signing", "Metadata edit by a document management system"]))
        elif text_changed or roles & CONTENT_ROLES:
            res.findings.append(Finding(
                id="revisions.content-changed",
                title=f"Revision {u['revision']} changes page content"
                      + (" after the document was signed" if after_signature else ""),
                severity=Severity.CRITICAL if after_signature else Severity.HIGH,
                confidence=Confidence.HIGH if text_changed else Confidence.MEDIUM,
                category="revisions",
                explanation=("An incremental update replaced or added page content streams, resources or pages. "
                             "The earlier version is still inside the file and can be extracted with "
                             "'pdfforensics extract-revisions'."
                             + (" The visible text differs between the versions (see evidence)." if text_changed else "")),
                evidence=evidence,
                benign_explanations=["Legitimate re-save by an editor after corrections",
                                     "Page added by an approved workflow (e.g. appended cover sheet)"]))
        elif roles & {"annotation", "form"}:
            res.findings.append(Finding(
                id="revisions.annotation-or-form-update",
                title=f"Revision {u['revision']} adds or changes annotations / form fields"
                      + (" after signing" if after_signature else ""),
                severity=Severity.HIGH if after_signature else Severity.MEDIUM,
                confidence=Confidence.MEDIUM, category="revisions",
                explanation=("Annotations (text boxes, stamps, drawings) and form values render on top of the page "
                             "and can change what the reader sees without touching the page content."),
                evidence=evidence,
                benign_explanations=["Form filling", "Review comments", "Signature widget appearance"]))
        else:
            res.findings.append(Finding(
                id="revisions.other-update", title=f"Revision {u['revision']} changes other objects",
                severity=Severity.LOW, confidence=Confidence.LOW, category="revisions",
                explanation="An incremental update exists, but its objects could not be linked to page content.",
                evidence=evidence))
    return res
