"""Render reports (JSON is the source of truth; Markdown is derived from it)."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

SEV_TAG = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "info": "[info]"}


def to_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str)


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence_lines(ev: dict[str, Any], limit: int = 12) -> list[str]:
    lines = []
    for k, v in ev.items():
        if isinstance(v, list):
            if not v:
                continue
            lines.append(f"  - **{k}**:")
            for item in v[:limit]:
                if isinstance(item, dict):
                    item = ", ".join(f"{ik}={iv}" for ik, iv in item.items())
                lines.append(f"    - `{_md_escape(item)[:300]}`")
            if len(v) > limit:
                lines.append(f"    - ... {len(v) - limit} more")
        elif isinstance(v, dict):
            if v:
                lines.append(f"  - **{k}**: `{_md_escape(json.dumps(v, default=str))[:400]}`")
        elif v not in (None, ""):
            lines.append(f"  - **{k}**: `{_md_escape(v)[:300]}`")
    return lines


def report_markdown(r: dict[str, Any], include_info: bool = True) -> str:
    f, v, t = r["file"], r["verdict"], r["tool"]
    out = [
        f"# PDF forensic report: {f['name']}",
        "",
        f"**Verdict:** `{v['label']}` (level: {v['level']}){'' if v['complete'] else ' - INCOMPLETE, see errors'}",
        "",
        f"> {v['summary']}",
        "",
        "| Field | Value |", "|---|---|",
        f"| File | `{_md_escape(f['path'])}` |",
        f"| Size | {f['size']:,} bytes |",
        f"| SHA-256 | `{f['sha256']}` |",
        f"| Analysed (UTC) | {f['analysed_at']} |",
        f"| Tool | {t['name']} {t['version']} (pikepdf {t['pikepdf']}, qpdf {t['qpdf']}, "
        f"pypdf {t['pypdf']}, pyHanko {t['pyhanko'] or 'not installed'}) |",
    ]
    rev = r["facts"].get("revisions", {})
    struct = r["facts"].get("structure", {})
    fp = r["facts"].get("fingerprint", {})
    sig = r["facts"].get("signatures", {})
    out += [
        f"| Pages | {struct.get('pages', '?')} |",
        f"| PDF version | {struct.get('pdf_version', '?')} (xref: {struct.get('xref_style', '?')}, "
        f"linearized: {struct.get('linearized', '?')}) |",
        f"| Revisions | {rev.get('revision_count', '?')} ({rev.get('incremental_updates', 0)} incremental update(s)) |",
        f"| Signatures | {sig.get('signature_count', 0)} |",
        f"| Producer / Creator | {_md_escape(fp.get('producer') or '-')} / {_md_escape(fp.get('creator') or '-')} |",
        f"| Pipeline fingerprint | `{fp.get('pipeline_hash', '-')}` ({fp.get('producer_family') or 'unclassified'}) |",
        "",
        "## Findings",
        "",
    ]
    shown = [x for x in r["findings"] if include_info or x["severity"] != "info"]
    if not shown:
        out.append("_No findings._")
    for x in shown:
        out.append(f"### {SEV_TAG[x['severity']]} {x['title']}")
        out.append("")
        out.append(f"`{x['id']}`, confidence: {x['confidence']}, category: {x['category']}")
        out.append("")
        out.append(x["explanation"])
        ev = _evidence_lines(x.get("evidence") or {})
        if ev:
            out += ["", "- Evidence:"] + ev
        if x.get("benign_explanations"):
            out += ["", "- Possible benign explanations: " + "; ".join(x["benign_explanations"])]
        out.append("")
    if r.get("errors"):
        out += ["## Analysis errors", ""]
        out += [f"- `{e['analyzer']}`: {_md_escape(e['error'])}" for e in r["errors"]]
        out.append("")
    out += ["## Method", "", f"- Verdict rule: {v['rule']}", f"- {v['disclaimer']}", ""]
    return "\n".join(out)


def batch_markdown(reports: list[dict[str, Any]], failures: list[dict[str, str]]) -> str:
    out = ["# PDF forensic batch summary", "",
           "| File | Verdict | Revisions | Signatures | Top findings | Pipeline |", "|---|---|---|---|---|---|"]
    groups: dict[str, list[str]] = defaultdict(list)
    for r in reports:
        fp = r["facts"].get("fingerprint", {})
        groups[fp.get("pipeline_hash", "?")].append(r["file"]["name"])
        out.append("| {} | `{}` | {} | {} | {} | `{}` |".format(
            _md_escape(r["file"]["name"]), r["verdict"]["label"],
            r["facts"].get("revisions", {}).get("revision_count", "?"),
            r["facts"].get("signatures", {}).get("signature_count", 0),
            ", ".join(r["verdict"]["top_findings"][:3]) or "-",
            fp.get("pipeline_hash", "?")))
    for fl in failures:
        out.append(f"| {_md_escape(fl['file'])} | `not-analysed` | - | - | {_md_escape(fl['error'])} | - |")
    out += ["", "## Documents grouped by production pipeline", ""]
    for h, names in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        fam = next((r["facts"]["fingerprint"].get("producer_family") for r in reports
                    if r["facts"].get("fingerprint", {}).get("pipeline_hash") == h), None)
        out.append(f"- `{h}` ({fam or 'unclassified'}): {', '.join(names)}")
    out.append("")
    return "\n".join(out)
