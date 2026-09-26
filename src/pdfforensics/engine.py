"""Run all analysers over one file and assemble a report with chain-of-custody data."""

from __future__ import annotations

import os
import platform
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import pikepdf
import pypdf

from pdfforensics import document, scoring, summary
from pdfforensics.model import Confidence, Finding, Report, Severity


def _tool_info() -> dict:
    from pdfforensics import __version__
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
    }
    if HAVE_PYHANKO:
        try:
            from importlib.metadata import version

            info["pyhanko"] = version("pyHanko")
        except Exception:
            info["pyhanko"] = "unknown"
    return info


def analyze_file(path: str | os.PathLike[str], options: document.Options | None = None) -> Report:
    from pdfforensics.analyzers import ALL

    started = datetime.now(timezone.utc)
    doc = document.load(path, options)
    findings: list[Finding] = []
    facts: dict = {}
    errors: list[dict[str, str]] = []
    try:
        for name, fn in ALL:
            try:
                r = fn(doc)
                findings.extend(r.findings)
                facts[name] = r.facts
            except Exception as exc:
                errors.append({"analyzer": name, "error": f"{type(exc).__name__}: {exc}",
                               "trace": traceback.format_exc(limit=3)})
                findings.append(Finding(
                    id="analysis.error", title=f"Analyser '{name}' failed",
                    severity=Severity.INFO, confidence=Confidence.HIGH, category="analysis",
                    explanation="This check could not be completed. Its absence must not be read as a clean result.",
                    evidence={"analyzer": name, "error": str(exc)}))
        file_info = {
            "path": str(Path(path).resolve()),
            "name": Path(path).name,
            "size": len(doc.data),
            "sha256": doc.sha256,
            "md5": doc.md5,
            "analysed_at": started.isoformat(),
        }
    finally:
        doc.close()
    findings.sort(key=lambda f: (scoring.effective(f), f.confidence), reverse=True)
    report = Report(file=file_info, tool=_tool_info(), verdict=scoring.verdict(findings, errors),
                    findings=findings, facts=facts, errors=errors)
    # the summary is generated from the finished report, exactly as it would be from saved JSON
    report.summary = summary.summarize(report.to_dict())
    return report
