"""Command-line interface.

    pdfforensics analyze FILE_OR_DIR... [--json OUT] [--markdown OUT] [--out-dir DIR] [--fail-on LEVEL]
    pdfforensics analyze FILE --summary [OUT]      # plain-language summary when done
    pdfforensics summarize REPORT.forensics.json... [-o OUT] [--json OUT]
    pdfforensics compare A.pdf B.pdf [--json OUT]
    pdfforensics extract-revisions FILE.pdf --out-dir DIR

Inputs are only read, never modified. Nothing is written next to the input unless you ask for it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pdfforensics import __version__, document, render, summary
from pdfforensics.compare import compare, compare_markdown
from pdfforensics.engine import SUPPORTED_SUFFIXES, analyze_file
from pdfforensics.model import Severity

LEVELS = {s.label: s for s in Severity}


def _collect(paths: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            files += sorted(x for x in it if x.is_file() and not x.is_symlink()
                            and x.suffix.lower().lstrip(".") in SUPPORTED_SUFFIXES)
        else:
            files.append(p)
    return files


def _options(a: argparse.Namespace) -> document.Options:
    return document.Options(password=a.password or "", max_pages=a.max_pages, max_objects=a.max_objects,
                            max_revisions=a.max_revisions, external_tools=not a.no_external_tools,
                            online_revocation=a.online_revocation)


def report_basename(r: dict) -> str:
    """<file name>.<sha256 prefix> - unique even for same-named files from different folders."""
    return f"{r['file']['name']}.{r['file']['sha256'][:12]}"


def _write(target: str | None, text: str) -> None:
    if target is None:
        return
    if target == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).write_text(text + "\n", encoding="utf-8")


def cmd_analyze(a: argparse.Namespace) -> int:
    files = _collect(a.paths, a.recursive)
    if not files:
        print("no PDF files found", file=sys.stderr)
        return 2
    reports, failures = [], []
    for f in files:
        try:
            reports.append(analyze_file(f, _options(a)).to_dict())
        except document.InputError as exc:
            failures.append({"file": str(f), "error": str(exc)})
            print(f"skip {f}: {exc}", file=sys.stderr)
    if a.out_dir:
        out = Path(a.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for r in reports:
            base = report_basename(r)
            (out / f"{base}.forensics.json").write_text(render.to_json(r) + "\n", encoding="utf-8")
            (out / f"{base}.forensics.md").write_text(report_md(r, a) + "\n", encoding="utf-8")
            (out / f"{base}.summary.md").write_text(_summary_doc([r], []) + "\n", encoding="utf-8")
        if len(files) > 1:
            (out / "batch-summary.md").write_text(render.batch_markdown(reports, failures), encoding="utf-8")
    payload = reports[0] if len(reports) == 1 and not failures else {
        "summary": summary.batch_summary(reports, failures), "reports": reports, "failures": failures}
    _write(a.json, render.to_json(payload))
    if a.markdown:
        md = report_md(reports[0], a) if len(reports) == 1 else "\n\n".join(
            [render.batch_markdown(reports, failures)] + [report_md(r, a) for r in reports])
        _write(a.markdown, md)
    if a.summary:
        _write(a.summary, _summary_doc(reports, failures))
    if not (a.json or a.markdown or a.out_dir or a.summary):
        if len(reports) == 1 and not failures:
            print(report_md(reports[0], a))
        else:
            print(render.batch_markdown(reports, failures))
    if failures and not reports:
        return 2
    if a.fail_on:
        threshold = LEVELS[a.fail_on]
        if any(LEVELS[r["verdict"]["level"]] >= threshold for r in reports):
            return 1
    return 0


def report_md(r: dict, a: argparse.Namespace) -> str:
    return render.report_markdown(r, include_info=not a.hide_info)


def _summary_doc(reports: list[dict], failures: list[dict]) -> str:
    """Stand-alone summary document: an executive summary for batches, then one summary per file."""
    parts = []
    if len(reports) + len(failures) > 1:
        parts += ["# PDF forensic summary", "",
                  summary.batch_summary_markdown(summary.batch_summary(reports, failures))]
    for r in reports:
        s = r.get("summary") or summary.summarize(r)
        heading = f"# Summary: {r['file']['name']}" if len(reports) == 1 and not failures else f"## {r['file']['name']}"
        parts.append(summary.summary_markdown(s, heading=heading))
        parts.append(f"_SHA-256 `{r['file']['sha256']}`, analysed {r['file']['analysed_at']} "
                     f"with {r['tool']['name']} {r['tool']['version']}._\n")
    return "\n".join(parts)


def cmd_summarize(a: argparse.Namespace) -> int:
    """Regenerate summaries from saved JSON reports (single reports or batch payloads)."""
    reports, failures = [], []
    for p in a.reports:
        try:
            data = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {p}: {exc}", file=sys.stderr)
            return 2
        if "reports" in data:
            reports += data["reports"]
            failures += data.get("failures", [])
        elif "findings" in data and "file" in data:
            reports.append(data)
        else:
            print(f"error: {p} is not a pdfforensics report", file=sys.stderr)
            return 2
    for r in reports:
        r["summary"] = summary.summarize(r)  # always rebuild with the current rules
    if a.json:
        payload = {"summary": summary.batch_summary(reports, failures),
                   "documents": [r["summary"] for r in reports]}
        _write(a.json, render.to_json(payload))
    _write(a.output or ("-" if not a.json else None), _summary_doc(reports, failures))
    return 0


def cmd_compare(a: argparse.Namespace) -> int:
    c = compare(a.a, a.b, _options(a))
    if a.json:
        _write(a.json, render.to_json(c))
    else:
        print(compare_markdown(c))
    return 0


def cmd_extract(a: argparse.Namespace) -> int:
    doc = document.load(a.file, _options(a))
    try:
        out = Path(a.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = doc.path.stem
        revs = doc.raw.revisions
        for rev in revs:
            target = out / f"{stem}.rev{rev.index:02d}-of-{len(revs):02d}.pdf"
            target.write_bytes(doc.data[:rev.end])
            print(f"{target}  ({rev.end:,} bytes)")
        if not revs:
            print("no revisions could be identified", file=sys.stderr)
            return 1
    finally:
        doc.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pdfforensics",
                                description="Explainable tampering and provenance analysis for PDF and Office documents.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--password", help="user password for encrypted PDFs")
    common.add_argument("--max-pages", type=int, default=500)
    common.add_argument("--max-objects", type=int, default=50_000)
    common.add_argument("--max-revisions", type=int, default=50)
    common.add_argument("--no-external-tools", action="store_true",
                        help="do not run optional local validators (Poppler pdfsig) even if installed")
    common.add_argument("--online-revocation", action="store_true",
                        help="let pdfsig contact OCSP responders to check revocation (network access; off by default)")
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", parents=[common],
                        help="analyse PDF / DOCX / XLSX / PPTX files or directories")
    an.add_argument("paths", nargs="+")
    an.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    an.add_argument("--json", metavar="FILE", help="write JSON report ('-' for stdout)")
    an.add_argument("--markdown", metavar="FILE", help="write Markdown report ('-' for stdout)")
    an.add_argument("--out-dir", metavar="DIR", help="write <name>.forensics.json/.md per file (+ batch summary)")
    an.add_argument("--summary", nargs="?", const="-", metavar="FILE",
                    help="write a plain-language summary when the analysis is done (stdout if FILE omitted)")
    an.add_argument("--hide-info", action="store_true", help="omit info-level findings from Markdown")
    an.add_argument("--fail-on", choices=list(LEVELS), help="exit 1 if any verdict is at or above this level")
    an.set_defaults(func=cmd_analyze)

    cp = sub.add_parser("compare", parents=[common], help="compare two PDFs")
    cp.add_argument("a")
    cp.add_argument("b")
    cp.add_argument("--json", metavar="FILE")
    cp.set_defaults(func=cmd_compare)

    sm = sub.add_parser("summarize", help="(re)generate summaries from saved *.forensics.json reports")
    sm.add_argument("reports", nargs="+")
    sm.add_argument("-o", "--output", metavar="FILE", help="write the Markdown summary to FILE (default stdout)")
    sm.add_argument("--json", metavar="FILE", help="also write the summaries as JSON ('-' for stdout)")
    sm.set_defaults(func=cmd_summarize)

    ex = sub.add_parser("extract-revisions", parents=[common],
                        help="write every revision of a PDF as a standalone PDF")
    ex.add_argument("file")
    ex.add_argument("--out-dir", required=True)
    ex.set_defaults(func=cmd_extract)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except document.InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
