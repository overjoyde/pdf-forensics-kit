"""Compare two PDFs: identity, metadata, pipeline fingerprint and page text."""

from __future__ import annotations

from typing import Any

from pdfforensics import document
from pdfforensics.analyzers import fingerprint, metadata
from pdfforensics.analyzers.revisions import extract_text_by_page, text_diff


def compare(path_a: str, path_b: str, options: document.Options | None = None) -> dict[str, Any]:
    a = document.load(path_a, options)
    b = document.load(path_b, options)
    try:
        fa, fb = fingerprint.analyze(a).facts, fingerprint.analyze(b).facts
        ma, mb = metadata.analyze(a).facts, metadata.analyze(b).facts
        ta = extract_text_by_page(a.data, a.options.max_pages)
        tb = extract_text_by_page(b.data, b.options.max_pages)
        info_keys = sorted(set(ma["info"]) | set(mb["info"]))
        meta_diff = {k: {"a": ma["info"].get(k), "b": mb["info"].get(k)}
                     for k in info_keys if ma["info"].get(k) != mb["info"].get(k)}
        fp_diff = {k: {"a": fa[k], "b": fb[k]} for k in fa
                   if k not in ("pipeline_hash",) and fa.get(k) != fb.get(k)}
        return {
            "a": {"path": str(a.path), "sha256": a.sha256, "size": len(a.data), "revisions": len(a.raw.revisions)},
            "b": {"path": str(b.path), "sha256": b.sha256, "size": len(b.data), "revisions": len(b.raw.revisions)},
            "identical": a.sha256 == b.sha256,
            "pipeline_similarity": fingerprint.similarity(fa, fb),
            "same_pipeline_hash": fa["pipeline_hash"] == fb["pipeline_hash"],
            "metadata_differences": meta_diff,
            "fingerprint_differences": fp_diff,
            "text_diff": text_diff(ta, tb),
        }
    finally:
        a.close()
        b.close()


def compare_markdown(c: dict[str, Any]) -> str:
    out = ["# PDF comparison", "",
           "| | A | B |", "|---|---|---|",
           f"| Path | `{c['a']['path']}` | `{c['b']['path']}` |",
           f"| SHA-256 | `{c['a']['sha256']}` | `{c['b']['sha256']}` |",
           f"| Size | {c['a']['size']:,} | {c['b']['size']:,} |",
           f"| Revisions | {c['a']['revisions']} | {c['b']['revisions']} |", "",
           f"- Byte-identical: **{c['identical']}**",
           f"- Pipeline similarity: **{c['pipeline_similarity']} / 100** (same pipeline hash: {c['same_pipeline_hash']})",
           ""]
    if c["fingerprint_differences"]:
        out += ["## Production differences", ""]
        out += [f"- **{k}**: A=`{v['a']}` B=`{v['b']}`" for k, v in c["fingerprint_differences"].items()]
        out.append("")
    if c["metadata_differences"]:
        out += ["## Metadata differences", ""]
        out += [f"- **{k}**: A=`{v['a']}` B=`{v['b']}`" for k, v in c["metadata_differences"].items()]
        out.append("")
    td = c["text_diff"]
    out += ["## Text differences", ""]
    if not td["added"] and not td["removed"]:
        out.append("_Extracted text is identical._")
    for e in td["removed"][:100]:
        out.append(f"- page {e['page']} only in A: `{e['text']}`")
    for e in td["added"][:100]:
        out.append(f"- page {e['page']} only in B: `{e['text']}`")
    out.append("")
    return "\n".join(out)
