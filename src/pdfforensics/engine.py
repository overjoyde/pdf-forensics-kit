"""Capture a file once, run the analysers for its format, and assemble the report."""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import traceback
from datetime import datetime, timezone
from typing import Callable

import pikepdf
import pypdf

from pdfforensics import capture, document, office, scoring, summary
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Report, Severity

# extension -> container family the extension promises
EXPECTED_FAMILY = {"pdf": "pdf", "doc": "ole", "xls": "ole", "ppt": "ole", "msg": "ole",
                   **{s: "zip" for s in office.OFFICE_SUFFIXES}}
SUPPORTED_SUFFIXES = {"pdf", *office.OFFICE_SUFFIXES, "doc", "xls", "ppt"}


def _tool_info(options: document.Options) -> dict:
    from pdfforensics import __version__
    from pdfforensics.analyzers.pdfsig import find_pdfsig, pdfsig_version
    from pdfforensics.analyzers.signatures import HAVE_PYHANKO

    info = {
        "name": "pdf-forensics-kit",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pikepdf": pikepdf.__version__,
        "qpdf": pikepdf.__libqpdf_version__,
        "pypdf": pypdf.__version__,
        "pyhanko": None,
        "pdfsig": None,
        "external_tools_enabled": options.external_tools,
        "network_access": options.online_revocation,
    }
    if HAVE_PYHANKO:
        try:
            from importlib.metadata import version

            info["pyhanko"] = version("pyHanko")
        except Exception:
            info["pyhanko"] = "unknown"
    exe = find_pdfsig()
    if exe and options.external_tools:
        info["pdfsig"] = pdfsig_version(exe) or "unknown"
    return info


def _input_findings(snap: capture.Snapshot) -> list[Finding]:
    out = []
    expected = EXPECTED_FAMILY.get(snap.suffix)
    if expected and expected != snap.format:
        out.append(Finding(
            id="input.extension-mismatch",
            title=f"File extension .{snap.suffix} does not match the content ({snap.format.upper()})",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="structure",
            explanation=("The file name promises a different format than the bytes contain. Viewers pick the "
                         "application by extension, so a renamed file can open in an unexpected program."),
            evidence={"extension": snap.suffix, "detected": snap.format},
            benign_explanations=["Renamed by mistake or by an upload system"]))
    return out


def _legacy_office(snap: capture.Snapshot) -> tuple[list[AnalyzerResult], list[dict[str, str]]]:
    r = AnalyzerResult(name="legacy_office")
    r.findings.append(Finding(
        id="office.legacy-format", title="Legacy binary Office file (OLE2) - not analysed in depth",
        severity=Severity.INFO, confidence=Confidence.HIGH, category="structure",
        explanation=("Legacy .doc/.xls/.ppt files use the OLE2 compound format, which this tool does not parse. "
                     "Use oletools (oleid, olevba) in an isolated environment, or ask for a DOCX/XLSX/PDF original."),
        evidence={"extension": snap.suffix}))
    return [r], [{"analyzer": "legacy_office", "error": "OLE2 compound files are not supported"}]


def _run_pdf(snap: capture.Snapshot, options: document.Options,
             collect: Callable[[str, Callable[[], AnalyzerResult]], None]) -> None:
    from pdfforensics.analyzers import ALL

    doc = document.load_snapshot(snap, options)
    try:
        for name, fn in ALL:
            collect(name, lambda fn=fn: fn(doc))
    finally:
        doc.close()


def analyze_file(path: str | os.PathLike[str], options: document.Options | None = None) -> Report:
    options = options or document.Options()
    started = datetime.now(timezone.utc)
    snap = capture.capture(path, options.max_bytes)

    findings: list[Finding] = _input_findings(snap)
    facts: dict = {}
    errors: list[dict[str, str]] = []

    def collect(name: str, fn: Callable[[], AnalyzerResult]) -> None:
        try:
            r = fn()
        except capture.InputError:
            raise
        except Exception as exc:
            errors.append({"analyzer": name, "error": f"{type(exc).__name__}: {exc}",
                           "trace": traceback.format_exc(limit=3)})
            findings.append(Finding(
                id="analysis.error", title=f"Analyser '{name}' failed",
                severity=Severity.INFO, confidence=Confidence.HIGH, category="analysis",
                explanation="This check could not be completed. Its absence must not be read as a clean result.",
                evidence={"analyzer": name, "error": str(exc)}))
            return
        findings.extend(r.findings)
        facts[r.name if r.name else name] = r.facts
        if r.error:
            errors.append({"analyzer": r.name or name, "error": r.error})

    fmt = snap.format
    if fmt == "pdf":
        _run_pdf(snap, options, collect)
    elif fmt == "zip":
        results = office.analyze(snap)   # raises InputError for non-Office ZIPs
        if results[0].facts.get("kind"):
            fmt = "ooxml"
        for r in results:
            collect(r.name, lambda r=r: r)
    elif fmt == "ole":
        results, errs = _legacy_office(snap)
        for r in results:
            collect(r.name, lambda r=r: r)
        errors.extend(errs)
    else:
        raise capture.InputError("unsupported format: expected PDF or Office (DOCX/XLSX/PPTX) - "
                                 "no %PDF- header or ZIP/OLE signature found")

    if not capture.path_still_matches(snap):
        findings.append(Finding(
            id="input.changed-after-capture", title="The file on disk changed or moved during analysis",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="analysis",
            explanation=("The report describes the captured bytes (see SHA-256), which no longer match the file "
                         "at the given path."),
            evidence={"path": str(snap.path)}))

    file_info = {
        "path": str(snap.path.resolve()),
        "name": snap.path.name,
        "format": fmt,
        "kind": facts.get("office_container", {}).get("kind") or ("pdf" if fmt == "pdf" else fmt),
        "size": snap.size,
        "sha256": snap.sha256,
        "md5": hashlib.md5(snap.data, usedforsecurity=False).hexdigest(),
        "analysed_at": started.isoformat(),
    }
    findings.sort(key=lambda f: (scoring.effective(f), f.confidence), reverse=True)
    report = Report(file=file_info, tool=_tool_info(options), verdict=scoring.verdict(findings, errors),
                    findings=findings, facts=facts, errors=errors)
    # the summary is generated from the finished report, exactly as it would be from saved JSON
    report.summary = summary.summarize(report.to_dict())
    return report
