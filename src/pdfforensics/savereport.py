"""Save analysis reports as Markdown files next to the analysed documents.

After an analysis the user can choose (yes/no) to save the report. The report is always a
Markdown file, written to the same folder as the document it describes:

    /case/invoice.pdf  ->  /case/invoice.pdf.forensics-report.md

An existing report is never overwritten; a timestamp is added instead. The document itself is
never touched. When several documents were analysed, each gets its own report next to it, and
a batch report is written to the common folder of all the documents.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from pdfforensics import render

SUFFIX = ".forensics-report.md"


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = path.name[: -len(".md")]
    candidate = path.with_name(f"{base}-{stamp}.md")
    n = 2
    while candidate.exists():
        candidate = path.with_name(f"{base}-{stamp}-{n}.md")
        n += 1
    return candidate


def report_path_for(document: str | os.PathLike[str]) -> Path:
    """Where the report for this document goes: same folder, '<name>.forensics-report.md'."""
    doc = Path(document)
    return _unique(doc.with_name(doc.name + SUFFIX))


def save_reports(reports: list[dict], failures: list[dict] | None = None) -> tuple[list[Path], list[str]]:
    """Write one Markdown report per document (plus a batch report for several documents).

    Returns (written paths, error messages). Errors such as a read-only folder are reported,
    not raised, so one unwritable folder does not lose the other reports.
    """
    failures = failures or []
    written: list[Path] = []
    errors: list[str] = []
    for r in reports:
        doc = Path(r["file"]["path"])
        target = report_path_for(doc)
        try:
            target.write_text(render.report_markdown(r) + "\n", encoding="utf-8")
            written.append(target)
        except OSError as exc:
            errors.append(f"could not write {target}: {exc.strerror or exc}")
    if len(reports) + len(failures) > 1 and reports:
        folders = [str(Path(r["file"]["path"]).parent) for r in reports]
        common = Path(os.path.commonpath(folders))
        target = _unique(common / f"forensics-batch-report-{datetime.now():%Y%m%d-%H%M%S}.md")
        try:
            target.write_text(render.batch_markdown(reports, failures) + "\n", encoding="utf-8")
            written.append(target)
        except OSError as exc:
            errors.append(f"could not write {target}: {exc.strerror or exc}")
    return written, errors


def ask_yes_no(question: str, default: bool = False) -> bool:
    """Ask a yes/no question on the terminal. Enter gives the default; Ctrl-C/Ctrl-D give 'no'."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"{question} {hint} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if not answer:
            return default
        if answer in ("y", "yes", "j", "ja"):
            return True
        if answer in ("n", "no", "nej"):
            return False
        print("Please answer y (yes) or n (no).")
