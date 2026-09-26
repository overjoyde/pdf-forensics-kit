"""Summarised PDF report: verdict, key findings and the edit timeline, rendered with reportlab.

reportlab is an optional extra ([report]) and is imported only when a PDF is written.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

INSTALL_HINT = "PDF reports need reportlab: pip install 'pdf-forensics-kit[report]'"

EVIDENCE_LABEL = {
    "claimed": "claimed by the file, can be forged",
    "signed": "inside a signature",
    "timestamped": "trusted timestamp (RFC 3161)",
}
TIMES_NOTE = ("Rows follow the order of the revisions in the file, which is fixed by its bytes. "
              "Times written into a file are set by the software that saved it and can be changed by anyone who "
              "edits the file. A signed time is covered by the signer's signature. Only an RFC 3161 timestamp "
              "from a timestamp authority independently shows that the document existed at that time.")


def available() -> bool:
    return importlib.util.find_spec("reportlab") is not None


def _t(value: Any, limit: int = 600) -> str:
    """Document-derived text made safe for reportlab markup. Characters the font lacks render as a box."""
    text = str(value if value is not None else "")
    if len(text) > limit:
        text = text[:limit] + "..."
    return escape(text)


def _when(e: dict[str, Any]) -> str:
    if not e.get("when"):
        return "no time recorded"
    return e["when"].replace("T", " ")


def _change_cell(e: dict[str, Any]) -> str:
    before, after = e.get("before") or [], e.get("after") or []
    if e.get("paired") and len(before) == len(after):  # never drop an unmatched line
        return "<br/>".join(f"{_t(b, 200)} &rarr; <b>{_t(a, 200)}</b>" for b, a in zip(before, after))
    parts = []
    if before:
        parts.append("<i>Before:</i><br/>" + "<br/>".join(_t(b, 200) for b in before))
    if after:
        parts.append("<i>After:</i><br/><b>" + "<br/>".join(_t(a, 200) for a in after) + "</b>")
    return "<br/>".join(parts) or "-"


def write_pdf_report(report: dict[str, Any], path: str | Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body, small, h1, h2 = styles["BodyText"], styles["BodyText"].clone("small", fontSize=8, leading=10), \
        styles["Title"], styles["Heading2"]
    f, v, s = report["file"], report["verdict"], report.get("summary") or {}
    story: list[Any] = [Paragraph(f"Document forensic report: {_t(f['name'])}", h1)]

    if not v.get("complete", True):
        failed = ", ".join(e.get("analyzer", "?") for e in report.get("errors", []))
        story.append(Paragraph(f"<b>Incomplete analysis:</b> {_t(failed)} could not run. Missing results from these "
                               "checks are not a clean result.", body))
    meta = [["Verdict", f"{v['label']} (level: {v['level']})"], ["Meaning", v.get("summary", "")],
            ["File", f["name"]], ["SHA-256", f["sha256"]], ["Size", f"{f['size']:,} bytes"],
            ["Analysed (UTC)", f.get("analysed_at", "")],
            ["Tool", f"pdf-forensics-kit {report.get('tool', {}).get('version', '')}"]]
    table = Table([[Paragraph(f"<b>{_t(k)}</b>", small), Paragraph(_t(val), small)] for k, val in meta],
                  colWidths=[35 * mm, 135 * mm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey)]))
    story += [table, Spacer(1, 6 * mm)]

    story.append(Paragraph("Summary", h2))
    if s.get("headline"):
        story.append(Paragraph(_t(s["headline"]), body))
    for k in s.get("key_findings", [])[:8]:
        line = f"&bull; <b>[{_t(k.get('severity', '').upper())}] {_t(k.get('title'))}</b>"
        if k.get("evidence"):
            line += f": {_t(k['evidence'], 300)}"
        story.append(Paragraph(line, body))

    story.append(Paragraph("Timeline of changes", h2))
    timeline = report.get("facts", {}).get("timeline")
    if timeline is None:
        story.append(Paragraph("<b>Timeline unavailable:</b> the timeline could not be built for this document.",
                               body))
    elif not timeline.get("events"):
        story.append(Paragraph("No edits, signatures or recorded save events were found.", body))
    else:
        rows = [[Paragraph(f"<b>{h}</b>", small) for h in ("When", "Time source", "What changed", "Before → after")]]
        for e in timeline["events"]:
            what = _t(e["what"]) + (" <b>(after signing)</b>" if e.get("after_signing") else "")
            if e.get("who"):
                what += f"<br/><i>{_t(e['who'], 120)}</i>"
            source = _t(e.get("time_source"))
            if e.get("time_evidence"):
                source += f"<br/><i>{_t(EVIDENCE_LABEL.get(e['time_evidence'], e['time_evidence']))}</i>"
            rows.append([Paragraph(_t(_when(e)), small), Paragraph(source or "-", small),
                         Paragraph(what, small), Paragraph(_change_cell(e), small)])
        tl = Table(rows, colWidths=[30 * mm, 38 * mm, 42 * mm, 60 * mm], repeatRows=1)
        tl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey)]))
        story.append(tl)
    story += [Spacer(1, 3 * mm), Paragraph(_t(TIMES_NOTE), small), Spacer(1, 6 * mm)]

    for title, key in (("Checked and found in order", "ruled_out"), ("Limitations", "limitations")):
        if s.get(key):
            story.append(Paragraph(title, h2))
            story += [Paragraph(f"&bull; {_t(x)}", body) for x in s[key]]
    story.append(Paragraph("Method", h2))
    story.append(Paragraph(_t(v.get("rule", "")), small))
    story.append(Paragraph(_t(v.get("disclaimer", "")), small))

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                      topMargin=18 * mm, bottomMargin=18 * mm,
                      title=f"Forensic report: {f['name']}").build(story)
