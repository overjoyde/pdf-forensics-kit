"""Office Open XML (DOCX / XLSX / PPTX and macro-enabled variants) analysis.

Works only on the captured bytes (a ZIP container) with strict resource limits:
- no extraction to disk,
- bounded entry count, uncompressed size and per-part XML size,
- XML with DOCTYPE/ENTITY declarations is refused (no entity expansion).

Checks: container anomalies, OPC conformance, core/app/custom metadata, Word tracked changes
(including the *deleted text* still stored in the file), hidden Word text, hidden Excel sheets,
hidden slides, comments, macros, embedded/ActiveX objects, external relationships (including
remote-template injection), DDE fields and XML signature parts.

Adapted from the author's document-forensics-agent (MIT) and extended.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any
from xml.etree import ElementTree as ET

from pdfforensics.capture import InputError, Snapshot
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import date_diff, iso

MAX_ENTRIES = 10_000
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
MAX_XML_BYTES = 25 * 1024 * 1024
BOMB_RATIO = 1_000
MAX_SNIPPETS = 40

OFFICE_SUFFIXES = {"docx": "docx", "docm": "docx", "dotx": "docx", "dotm": "docx",
                   "xlsx": "xlsx", "xlsm": "xlsx", "xltx": "xlsx", "xltm": "xlsx",
                   "pptx": "pptx", "pptm": "pptx", "potx": "pptx", "potm": "pptx", "ppsx": "pptx", "ppsm": "pptx"}
MACRO_SUFFIXES = {"docm", "dotm", "xlsm", "xltm", "pptm", "potm", "ppsm"}
ROOTS = {
    "docx": ("word/document.xml", "wordprocessingml.document.main+xml", "wordprocessingml.template.main+xml",
             "ms-word.document.macroEnabled.main+xml", "ms-word.template.macroEnabledTemplate.main+xml"),
    "xlsx": ("xl/workbook.xml", "spreadsheetml.sheet.main+xml", "spreadsheetml.template.main+xml",
             "ms-excel.sheet.macroEnabled.main+xml", "ms-excel.template.macroEnabled.main+xml"),
    "pptx": ("ppt/presentation.xml", "presentationml.presentation.main+xml", "presentationml.template.main+xml",
             "presentationml.slideshow.main+xml", "ms-powerpoint.presentation.macroEnabled.main+xml",
             "ms-powerpoint.slideshow.macroEnabled.main+xml", "ms-powerpoint.template.macroEnabled.main+xml"),
}


def _ln(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(el: ET.Element, local: str) -> str | None:
    for k, v in el.attrib.items():
        if _ln(k) == local:
            return v
    return None


class _Pkg:
    def __init__(self, zf: zipfile.ZipFile):
        self.zf = zf
        self.names = [i.filename for i in zf.infolist()]
        self.nameset = set(self.names)
        self.refused: list[str] = []

    def xml(self, name: str) -> ET.Element | None:
        try:
            info = self.zf.getinfo(name)
        except KeyError:
            return None
        if info.file_size > MAX_XML_BYTES:
            self.refused.append(f"{name}: larger than {MAX_XML_BYTES // 1_000_000} MB")
            return None
        try:
            data = self.zf.read(info)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
            self.refused.append(f"{name}: {exc}")
            return None
        head = data[:4096].upper()
        if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
            self.refused.append(f"{name}: DOCTYPE/ENTITY declarations are not parsed")
            return None
        try:
            return ET.fromstring(data)
        except ET.ParseError as exc:
            self.refused.append(f"{name}: not well-formed XML ({exc})")
            return None


def detect_kind(names: set[str]) -> str | None:
    for kind, (root, *_rest) in ROOTS.items():
        if root in names:
            return kind
    return None


def is_office_zip(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return detect_kind({i.filename for i in zf.infolist()}) is not None
    except zipfile.BadZipFile:
        return False


# ------------------------------------------------------------------------------------ container

def _container(pkg: _Pkg, infos: list[zipfile.ZipInfo], kind: str | None, suffix: str) -> AnalyzerResult:
    res = AnalyzerResult(name="office_container")
    total_u = sum(i.file_size for i in infos)
    res.facts.update({"entries": len(infos), "uncompressed_bytes": total_u,
                      "compressed_bytes": sum(i.compress_size for i in infos), "kind": kind})
    zip_times = [i.date_time for i in infos if i.date_time and i.date_time[0] > 1980]
    if zip_times:
        res.facts["zip_timestamps"] = {"earliest": datetime(*min(zip_times)).isoformat(),
                                       "latest": datetime(*max(zip_times)).isoformat()}

    def add(fid, title, sev, conf, expl, ev=None, benign=()):
        res.findings.append(Finding(fid, title, sev, conf, "structure", expl, ev or {}, list(benign)))

    dups = sorted(n for n, c in Counter(pkg.names).items() if c > 1)
    if dups:
        add("office.duplicate-parts", "Duplicate part names in the package", Severity.HIGH, Confidence.HIGH,
            "Two parts share a name, so different Office versions or tools may display different content.",
            {"parts": dups[:50]})
    unsafe = sorted(n for n in pkg.names
                    if n.replace("\\", "/").startswith(("/", "../")) or "/../" in n.replace("\\", "/")
                    or re.match(r"^[A-Za-z]:[/\\]", n))
    if unsafe:
        add("office.unsafe-paths", "Path-traversal entries in the package", Severity.HIGH, Confidence.HIGH,
            "Entries with absolute or '..' paths never occur in genuine Office files. They target unzip tools.",
            {"parts": unsafe[:50]})
    enc = sorted(i.filename for i in infos if i.flag_bits & 0x1)
    if enc:
        add("office.encrypted-parts", "Encrypted ZIP entries", Severity.MEDIUM, Confidence.HIGH,
            "Some parts are ZIP-encrypted. Office never does this, and the parts could not be inspected.",
            {"parts": enc[:50]})
    bombs = [{"part": i.filename, "ratio": round(i.file_size / max(i.compress_size, 1))}
             for i in infos if i.file_size > 1_000_000 and i.file_size / max(i.compress_size, 1) > BOMB_RATIO]
    if bombs:
        add("office.compression-bomb", "Extreme compression ratio (decompression-bomb pattern)",
            Severity.HIGH, Confidence.HIGH, "Parts expand at a ratio that is typical of decompression bombs.",
            {"parts": bombs[:20]})
    if len(infos) > MAX_ENTRIES or total_u > MAX_TOTAL_UNCOMPRESSED:
        add("office.resource-limit", "Package exceeds safe inspection limits", Severity.MEDIUM, Confidence.HIGH,
            "Too many entries or too much uncompressed data; inspection stopped before decompression.",
            {"entries": len(infos), "uncompressed_bytes": total_u})

    expected = OFFICE_SUFFIXES.get(suffix)
    if kind is None:
        add("office.not-an-office-package", "ZIP file without Office document parts",
            Severity.HIGH, Confidence.HIGH,
            f"The file has an Office extension (.{suffix}) but contains no Word, Excel or PowerPoint root part. "
            "It is an ordinary ZIP archive, or a damaged or disguised package.",
            {"extension": suffix})
        return res
    if expected and expected != kind:
        add("office.extension-mismatch", f"Extension .{suffix} but the package is a {kind.upper()}",
            Severity.MEDIUM, Confidence.HIGH,
            "The file name claims a different Office application than the package content.",
            {"extension": suffix, "detected": kind}, ["File renamed by mistake"])

    # OPC conformance
    issues = []
    root_part, *ctypes = ROOTS[kind]
    ct = pkg.xml("[Content_Types].xml")
    if ct is None:
        issues.append("[Content_Types].xml missing or unreadable")
    else:
        declared = {(el.get("PartName") or "").lstrip("/"): el.get("ContentType", "")
                    for el in ct if _ln(el.tag) == "Override"}
        if not any(frag in declared.get(root_part, "") for frag in ctypes):
            issues.append(f"no matching content type declared for /{root_part}")
        res.facts["root_content_type"] = declared.get(root_part)
    rels = pkg.xml("_rels/.rels")
    if rels is None:
        issues.append("_rels/.rels missing or unreadable")
    elif not any((el.get("Type") or "").endswith("/officeDocument")
                 and (el.get("Target") or "").lstrip("/") == root_part for el in rels):
        issues.append(f"no root officeDocument relationship to {root_part}")
    if issues:
        add("office.opc-nonconformant", "Package manifest or root relationship is inconsistent",
            Severity.MEDIUM, Confidence.MEDIUM,
            "Genuine Office output always declares its main part consistently. Hand-built or rebuilt packages often do not.",
            {"issues": issues}, ["Produced by a third-party generator library"])
    return res


# ------------------------------------------------------------------------------------ metadata

def _flat(root: ET.Element | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if root is None:
        return out
    for child in root:
        text = (child.text or "").strip()
        if text:
            out[_ln(child.tag)] = text[:500]
    return out


def _custom(root: ET.Element | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if root is None:
        return out
    for prop in root:
        val = next(iter(prop), None)
        out[prop.get("name", _ln(prop.tag))] = ((val.text or "").strip() if val is not None else "")[:500]
    return out


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _metadata(pkg: _Pkg) -> AnalyzerResult:
    res = AnalyzerResult(name="office_metadata")
    core, app, custom = _flat(pkg.xml("docProps/core.xml")), _flat(pkg.xml("docProps/app.xml")), \
        _custom(pkg.xml("docProps/custom.xml"))
    res.facts.update({"core": core, "app": app, "custom": custom})
    created, modified = _parse_dt(core.get("created")), _parse_dt(core.get("modified"))
    printed = _parse_dt(core.get("lastPrinted"))
    now = datetime.now(timezone.utc)

    def add(fid, title, sev, conf, expl, ev=None, benign=()):
        res.findings.append(Finding(fid, title, sev, conf, "metadata", expl, ev or {}, list(benign)))

    if not core and not app:
        add("office.metadata-absent", "No document properties", Severity.INFO, Confidence.HIGH,
            "docProps/core.xml and app.xml are missing. Office always writes them; generators and scrubbers may not.",
            benign=["Generated by a library", "Metadata removed with 'Inspect Document'"])
    if created and modified:
        delta, exact = date_diff(modified, created)
        if delta < -(timedelta(minutes=2) if exact else timedelta(hours=14)):
            add("office.modified-before-created", "Last-modified date is earlier than the creation date",
                Severity.MEDIUM, Confidence.HIGH if exact else Confidence.MEDIUM,
                "The core properties give an impossible order of events.",
                {"created": iso(created), "modified": iso(modified), "difference": str(delta)},
                ["Wrong clock on the editing machine", "Properties edited by hand"])
    if printed and created:
        delta, exact = date_diff(printed, created)
        if exact and delta < -timedelta(minutes=2):
            add("office.printed-before-created", "Last-printed date is earlier than the creation date",
                Severity.LOW, Confidence.MEDIUM,
                "The document says it was printed before it was created. That is typical of a file saved as a copy "
                "of an older document (a template or earlier version) and then edited.",
                {"created": iso(created), "last_printed": iso(printed)},
                ["'Save as' from an older document, which is common and legitimate"])
    for label, d in (("created", created), ("modified", modified), ("lastPrinted", printed)):
        if d:
            dd = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            if dd - now > timedelta(days=1):
                add("office.future-date", f"Property '{label}' lies in the future", Severity.MEDIUM, Confidence.HIGH,
                    "A timestamp after the time of analysis indicates a manually set date or a wrong clock.",
                    {"field": label, "value": iso(d)})
    creator, editor = core.get("creator", ""), core.get("lastModifiedBy", "")
    if creator and editor and creator != editor:
        add("office.different-editor", "Last edited by a different person than the author",
            Severity.INFO, Confidence.HIGH,
            "The author and last-modified-by fields name different users. This is normal in shared workflows, "
            "but worth knowing when a single person is supposed to have produced the document.",
            {"creator": creator, "last_modified_by": editor})
    try:
        revision = int(core.get("revision", "0"))
        total_time = int(app.get("TotalTime", "-1"))
    except ValueError:
        revision, total_time = 0, -1
    res.facts["editing"] = {"revision": revision, "total_edit_minutes": total_time}
    if revision >= 2 and total_time == 0:
        add("office.zero-edit-time", "Saved several times with zero recorded editing time",
            Severity.LOW, Confidence.LOW,
            ("Word/Excel count editing minutes. Many revisions with 0 minutes is typical of documents produced by "
             "a generator or re-saved by a converter, not typed by a person."),
            {"revision": revision, "total_edit_minutes": total_time},
            ["Generated by a document system", "Converted from another format"])
    template = app.get("Template", "")
    if template.lower().startswith(("http:", "https:", "\\\\")):
        add("office.remote-template-name", "Template property points to a remote location",
            Severity.MEDIUM, Confidence.MEDIUM,
            "The template is named by URL or UNC path, as in remote-template injection.", {"template": template})
    return res


# ------------------------------------------------------------------------------------ content

def _word(pkg: _Pkg) -> tuple[dict[str, Any], list[Finding]]:
    facts: dict[str, Any] = {}
    findings: list[Finding] = []
    parts = ["word/document.xml"] + sorted(n for n in pkg.names
                                           if re.match(r"word/(header|footer|footnotes|endnotes)\d*\.xml$", n))
    ins = dels = moves = 0
    authors: set[str] = set()
    deleted: list[str] = []
    inserted: list[str] = []
    changes: list[dict[str, str]] = []
    hidden: list[str] = []
    dde: list[str] = []
    for part in parts:
        root = pkg.xml(part)
        if root is None:
            continue
        for el in root.iter():
            tag = _ln(el.tag)
            if tag in ("ins", "del", "moveFrom", "moveTo"):
                a = _attr(el, "author")
                if a:
                    authors.add(a)
                if tag == "ins":
                    ins += 1
                    txt = "".join(t.text or "" for t in el.iter() if _ln(t.tag) == "t").strip()
                    if txt and len(inserted) < MAX_SNIPPETS:
                        inserted.append(f"{part}: {txt[:200]}")
                elif tag == "del":
                    dels += 1
                    txt = "".join(t.text or "" for t in el.iter() if _ln(t.tag) == "delText").strip()
                    if txt and len(deleted) < MAX_SNIPPETS:
                        deleted.append(f"{part}: {txt[:200]}")
                else:
                    moves += 1
                    txt = ""
                if tag in ("ins", "del") and txt and len(changes) < MAX_SNIPPETS:
                    changes.append({"type": tag, "author": a or "", "date": _attr(el, "date") or "",
                                    "text": txt[:200], "part": part})
            elif tag == "r":
                rpr = next((c for c in el if _ln(c.tag) == "rPr"), None)
                if rpr is not None:
                    van = next((c for c in rpr if _ln(c.tag) in ("vanish", "specVanish")), None)
                    if van is not None and _attr(van, "val") not in ("0", "false"):
                        txt = "".join(t.text or "" for t in el.iter() if _ln(t.tag) == "t").strip()
                        if txt and len(hidden) < MAX_SNIPPETS:
                            hidden.append(f"{part}: {txt[:200]}")
            elif tag in ("instrText", "fldSimple"):
                code = (el.text or "") if tag == "instrText" else (_attr(el, "instr") or "")
                if re.search(r"\bDDE(AUTO)?\b", code, re.I):
                    dde.append(code.strip()[:200])
    settings = pkg.xml("word/settings.xml")
    tracking_on = False
    rsids = 0
    if settings is not None:
        for el in settings.iter():
            tag = _ln(el.tag)
            if tag == "trackRevisions" and _attr(el, "val") not in ("0", "false"):
                tracking_on = True
            elif tag == "rsid":
                rsids += 1
    comments_root = pkg.xml("word/comments.xml")
    comment_els = [c for c in comments_root if _ln(c.tag) == "comment"] if comments_root is not None else []
    comment_authors = sorted({_attr(c, "author") or "?" for c in comment_els})
    n_comments = len(comment_els)
    facts.update({"tracked_insertions": ins, "tracked_deletions": dels, "tracked_moves": moves,
                  "revision_authors": sorted(authors), "track_changes_on": tracking_on,
                  "editing_sessions_rsid": rsids, "comments": n_comments, "comment_authors": comment_authors,
                  "hidden_text_runs": len(hidden), "tracked_changes": changes})
    if ins or dels or moves:
        findings.append(Finding(
            "office.tracked-changes", f"Tracked changes still stored in the document ({ins} insertion(s), "
                                      f"{dels} deletion(s))",
            Severity.MEDIUM if deleted else Severity.LOW, Confidence.HIGH, "revisions",
            ("The file keeps unaccepted tracked changes. Deleted text is still inside the file even when markup "
             "is hidden in the viewer. Check it against the visible version."),
            {"deleted_text": deleted, "inserted_text": inserted, "authors": sorted(authors)},
            ["Normal review workflow where changes were not yet accepted"]))
    elif tracking_on:
        findings.append(Finding(
            "office.track-changes-enabled", "Track changes is switched on", Severity.INFO, Confidence.HIGH,
            "revisions", "Change tracking is enabled, but no pending changes are stored.", {}))
    if hidden:
        findings.append(Finding(
            "office.hidden-text", "Hidden (vanished) text in the document", Severity.MEDIUM, Confidence.HIGH,
            "content", ("Runs formatted as hidden are not shown or printed by default, but are part of the text, "
                        "including for search and automated extraction."),
            {"text": hidden}, ["Instructions or placeholders in a template"]))
    if n_comments:
        findings.append(Finding(
            "office.comments", f"{n_comments} comment(s)", Severity.INFO, Confidence.HIGH, "content",
            "Review comments are present; they can reveal authorship and editing history.",
            {"authors": comment_authors}))
    if dde:
        findings.append(Finding(
            "office.dde-field", "DDE field (can run commands when fields update)", Severity.HIGH, Confidence.HIGH,
            "active-content", "DDE/DDEAUTO field codes are a known way to start programs from Word documents.",
            {"fields": dde[:10]}))
    return facts, findings


def _excel(pkg: _Pkg) -> tuple[dict[str, Any], list[Finding]]:
    facts: dict[str, Any] = {}
    findings: list[Finding] = []
    wb = pkg.xml("xl/workbook.xml")
    sheets, hidden, very_hidden, hidden_names = [], [], [], []
    if wb is not None:
        for el in wb.iter():
            tag = _ln(el.tag)
            if tag == "sheet":
                name, state = el.get("name", "?"), el.get("state", "visible")
                sheets.append({"name": name, "state": state})
                (very_hidden if state == "veryHidden" else hidden if state == "hidden" else []).append(name)
            elif tag == "definedName" and el.get("hidden") in ("1", "true"):
                hidden_names.append(el.get("name", "?"))
    ext = sorted(n for n in pkg.names if n.startswith("xl/externalLinks/") and n.endswith(".xml"))
    comments = sorted(n for n in pkg.names if re.match(r"xl/(comments\d*|threadedComments/.*)\.xml$", n))
    facts.update({"sheets": sheets, "external_link_parts": ext, "comment_parts": comments,
                  "hidden_defined_names": hidden_names[:50]})
    if very_hidden:
        findings.append(Finding(
            "office.very-hidden-sheets", "Very-hidden worksheets", Severity.MEDIUM, Confidence.HIGH, "content",
            ("'veryHidden' sheets cannot be unhidden from the Excel user interface, only through VBA or by editing "
             "the file. Visible figures can depend on them without the reader knowing."),
            {"sheets": very_hidden}, ["Lookup tables in spreadsheet tools and templates"]))
    if hidden:
        findings.append(Finding(
            "office.hidden-sheets", "Hidden worksheets", Severity.LOW, Confidence.HIGH, "content",
            "Hidden sheets are not shown but can feed values into visible cells.", {"sheets": hidden},
            ["Helper/lookup sheets"]))
    if ext:
        findings.append(Finding(
            "office.external-workbook-links", "Links to external workbooks", Severity.LOW, Confidence.HIGH,
            "content", "Values can come from other files that are not part of this document.", {"parts": ext}))
    if comments:
        findings.append(Finding("office.comments", "Cell comments present", Severity.INFO, Confidence.HIGH,
                                "content", "Comments can reveal authorship and editing history.", {"parts": comments}))
    return facts, findings


def _powerpoint(pkg: _Pkg) -> tuple[dict[str, Any], list[Finding]]:
    facts: dict[str, Any] = {}
    findings: list[Finding] = []
    slides = sorted((n for n in pkg.names if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                    key=lambda n: int(re.search(r"(\d+)", n.rsplit("/", 1)[1]).group(1)))
    hidden = []
    for s in slides:
        root = pkg.xml(s)
        if root is not None and root.get("show") in ("0", "false"):
            hidden.append(s.rsplit("/", 1)[1])
    comments = sorted(n for n in pkg.names if n.startswith(("ppt/comments/", "ppt/commentAuthors")))
    facts.update({"slides": len(slides), "hidden_slides": hidden, "comment_parts": comments})
    if hidden:
        findings.append(Finding("office.hidden-slides", "Hidden slides", Severity.LOW, Confidence.HIGH, "content",
                                "Hidden slides are skipped in a slide show but remain in the file.",
                                {"slides": hidden}, ["Backup slides"]))
    if comments:
        findings.append(Finding("office.comments", "Slide comments present", Severity.INFO, Confidence.HIGH,
                                "content", "Comments can reveal authorship and editing history.", {"parts": comments}))
    return facts, findings


# ------------------------------------------------------------------------------------ active content

def _active(pkg: _Pkg, suffix: str) -> AnalyzerResult:
    res = AnalyzerResult(name="office_active")
    names = pkg.names
    macros = sorted(n for n in names if posixpath.basename(n).lower() in ("vbaproject.bin", "vbadata.xml"))
    xlm = sorted(n for n in names if n.startswith("xl/macrosheets/"))
    embeds = sorted(n for n in names if "/embeddings/" in n.lower())
    activex = sorted(n for n in names if "/activex/" in n.lower())
    sigs = sorted(n for n in names if n.startswith("_xmlsignatures/"))
    external: list[dict[str, str]] = []
    for n in names:
        if not n.endswith(".rels"):
            continue
        root = pkg.xml(n)
        if root is None:
            continue
        for rel in root:
            if (rel.get("TargetMode") or "").lower() == "external":
                external.append({"part": n, "type": (rel.get("Type") or "").rsplit("/", 1)[-1],
                                 "target": (rel.get("Target") or "")[:500]})
    res.facts.update({"macros": macros, "excel4_macrosheets": xlm, "embedded_objects": embeds, "activex": activex,
                      "xml_signature_parts": sigs, "external_relationships": external[:200]})

    def add(fid, title, sev, conf, expl, ev=None, benign=(), cat="active-content"):
        res.findings.append(Finding(fid, title, sev, conf, cat, expl, ev or {}, list(benign)))

    if macros or xlm:
        wrong_ext = suffix not in MACRO_SUFFIXES
        add("office.macros", "VBA / Excel 4 macros present" + (f" in a .{suffix} file" if wrong_ext else ""),
            Severity.HIGH, Confidence.HIGH,
            ("The package contains macro code. Do not enable it; analyse it statically (e.g. olevba) in isolation."
             + (" Macro-free extensions such as .docx/.xlsx should not contain macros at all. The file was probably "
                "renamed." if wrong_ext else "")),
            {"parts": macros + xlm}, ["Internal business tools built on macros"])
    templates = [e for e in external if e["type"] == "attachedTemplate"]
    if templates:
        add("office.remote-template", "Document loads a template from a remote location", Severity.HIGH,
            Confidence.HIGH, "Remote template injection makes Word fetch and run content from the web when opened.",
            {"relationships": templates})
    others = [e for e in external if e["type"] not in ("attachedTemplate", "hyperlink")]
    if others:
        add("office.external-content", "External content relationships", Severity.MEDIUM, Confidence.HIGH,
            ("The document pulls content (images, OLE links, data) from outside the file when opened. It can "
             "display something different from what is stored, and reveals when it is opened."),
            {"relationships": others[:30]}, ["Linked images or data sources in corporate templates"])
    links = [e for e in external if e["type"] == "hyperlink"]
    if links:
        add("office.hyperlinks", f"{len(links)} external hyperlink(s)", Severity.INFO, Confidence.HIGH,
            "External URLs referenced by hyperlinks.", {"targets": sorted({e['target'] for e in links})[:50]})
    if embeds:
        add("office.embedded-objects", f"{len(embeds)} embedded object(s)", Severity.MEDIUM, Confidence.HIGH,
            "Embedded files or OLE objects can carry other documents or executables. Extract them and review "
            "them separately.", {"parts": embeds[:50]}, ["Embedded spreadsheets or charts"])
    if activex:
        add("office.activex", "ActiveX controls", Severity.MEDIUM, Confidence.HIGH,
            "ActiveX controls can execute code when enabled.", {"parts": activex[:50]})
    if sigs:
        add("office.xml-signature", "Office XML digital signature parts present", Severity.INFO, Confidence.HIGH,
            ("The package carries XML digital signature parts. This tool does not validate them cryptographically. "
             "Verify them in Office (File > Info > View Signatures) or with a trusted validator."),
            {"parts": sigs}, cat="signatures")
    return res


def _fingerprint(meta: dict[str, Any], kind: str) -> AnalyzerResult:
    res = AnalyzerResult(name="fingerprint")
    app = meta.get("app", {})
    core = meta.get("core", {})

    def norm(v: str) -> str:
        return " ".join(v.casefold().split())[:200]

    fp = {
        "format": kind,
        "producer": app.get("Application", ""),
        "creator": core.get("creator", ""),
        "producer_normalized": norm(app.get("Application", "")),
        "creator_normalized": "",
        "app_version": app.get("AppVersion", ""),
        "company": app.get("Company", ""),
        "template": app.get("Template", ""),
        "producer_family": app.get("Application") or None,
    }
    stable = "|".join([kind, fp["producer_normalized"], norm(fp["app_version"]), norm(fp["company"]),
                       norm(fp["template"])])
    fp["pipeline_hash"] = hashlib.sha256(stable.encode()).hexdigest()[:16]
    res.facts.update(fp)
    return res


# ------------------------------------------------------------------------------------ entry point

def analyze(snap: Snapshot) -> list[AnalyzerResult]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(snap.data))
    except zipfile.BadZipFile as exc:
        raise InputError(f"ZIP container could not be read: {exc}") from exc
    with zf:
        infos = zf.infolist()
        pkg = _Pkg(zf)
        kind = detect_kind(pkg.nameset)
        if kind is None and snap.suffix not in OFFICE_SUFFIXES:
            raise InputError("ZIP archive that is not an Office document - unsupported format")
        container = _container(pkg, infos, kind, snap.suffix)
        results = [container]
        limited = (len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED
                   or any(f.id == "office.compression-bomb" for f in container.findings))
        if kind is None or limited:
            container.error = ("package not decompressed: " +
                               ("no Office root part" if kind is None else "safety limits exceeded"))
            return results
        meta = _metadata(pkg)
        results.append(meta)
        content = AnalyzerResult(name="office_content")
        facts, findings = {"docx": _word, "xlsx": _excel, "pptx": _powerpoint}[kind](pkg)
        content.facts.update(facts)
        content.findings.extend(findings)
        results.append(content)
        results.append(_active(pkg, snap.suffix))
        results.append(_fingerprint(meta.facts, kind))
        if pkg.refused:
            container.facts["parts_not_parsed"] = pkg.refused[:50]
            container.findings.append(Finding(
                "office.parts-not-parsed", f"{len(pkg.refused)} part(s) could not be parsed safely",
                Severity.LOW, Confidence.MEDIUM, "structure",
                "Some XML parts were too large, malformed or contained DTD/entity declarations. They were skipped.",
                {"parts": pkg.refused[:20]}))
        return results
