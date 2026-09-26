"""Plain-language summary of a finished forensic analysis.

``summarize(report)`` is a pure function of a report dictionary, the same JSON the tool writes.
It therefore runs automatically at the end of every analysis, and it can also be regenerated
later from saved JSON reports (``pdfforensics summarize *.forensics.json``).

The summary answers four questions for a non-technical reader:
  1. What is the outcome? (headline + verdict)
  2. What was found that matters? (key findings, with the decisive evidence)
  3. What was checked and found in order? (ruled out)
  4. What should happen next, and what are the limits? (actions, limitations)
"""

from __future__ import annotations

from collections import Counter
from typing import Any

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ATTENTION = {"medium", "high", "critical"}

# Next steps per finding id (most specific first). Wording is deliberately practical.
ACTIONS: dict[str, str] = {
    "revisions.content-changed": ("Extract the earlier revision(s) with `pdfforensics extract-revisions` and compare "
                                  "them with the current version. Ask the issuer for the original document."),
    "signature.broken": "Treat the document as altered after signing. Obtain a fresh copy directly from the signer.",
    "signature.disallowed-modification": ("Ask the signer to confirm the post-signing changes, or obtain the signed "
                                          "revision (extract-revisions) as the authoritative version."),
    "signature.malformed-byterange": "Do not rely on the signature. Have the document re-issued and re-signed.",
    "signature.bytes-after-last-signature": ("Check the revision findings to see whether the unsigned additions change "
                                             "visible content or are only validation data."),
    "revisions.annotation-or-form-update": "Review annotations and form values against the original issuer's copy.",
    "metadata.editor-tool": ("Ask the submitter why the document passed through a general-purpose PDF editor, and "
                             "request the original file from the issuing system."),
    "metadata.modified-before-created": "Verify the document dates with the issuer; the timestamps are inconsistent.",
    "metadata.future-date": "Verify the document dates with the issuer; a timestamp lies in the future.",
    "content.invisible-text": ("Compare copied/extracted text with what is visible. Automated systems may read the "
                               "hidden text."),
    "content.print-only-annotations": "Print or print-preview the document and compare it with the on-screen view.",
    "content.layer-view-print-differs": "Compare the printed and on-screen versions; layers differ between them.",
    "active.launch-action": "Open only in a sandboxed viewer, and do not allow external programs to run.",
    "active.javascript": "Open in a viewer with JavaScript disabled, and do not trust dynamically filled fields.",
    "active.embedded-files": "Extract the attachments in an isolated environment and review them as separate evidence.",
    "active.xfa": "Render the form in Adobe Reader and in another viewer; XFA content can differ between viewers.",
    "active.submit-or-import": "Check where form data is sent before filling in or submitting the form.",
    "structure.data-after-eof": "Extract the bytes after the final %%EOF for separate inspection.",
    "pdfsig.integrity-failure": "Treat the document as altered after signing. Obtain a fresh copy directly from the signer.",
    "pdfsig.certificate-revoked": ("Check whether the certificate was revoked before the signing time. Escalate to "
                                   "the approved trust service."),
    "signature.validators-disagree": "Have the signature examined manually; the two validators disagree.",
    "input.extension-mismatch": "Ask why the file was renamed, and obtain it with its original name and format.",
    "office.tracked-changes": ("Open the document with 'All Markup' shown and compare the deleted text in the "
                               "evidence with the visible version."),
    "office.hidden-text": "Show hidden text (Word: File > Options > Display) and compare it with the printed version.",
    "office.very-hidden-sheets": ("Inspect the very-hidden sheets (VBA editor or a ZIP viewer) and check whether "
                                  "visible figures depend on them."),
    "office.macros": "Do not enable macros. Analyse them statically (olevba) in an isolated environment.",
    "office.remote-template": "Do not open the document online. Block the template URL and analyse it in isolation.",
    "office.dde-field": "Do not update fields. Analyse the document in isolation.",
    "office.external-content": "Review the external targets before letting Office load them.",
    "office.embedded-objects": "Extract embedded objects in isolation and review them as separate evidence.",
    "office.modified-before-created": "Verify the document dates with the author or document-management system.",
    "office.not-an-office-package": "Obtain the original file from the source system; this is not an Office document.",
}

# Stronger verification sources, in descending order of evidential value. Used as the closing
# recommendation whenever a document needs attention, because structural analysis alone rarely settles it.
VERIFICATION_HIERARCHY = [
    "a valid digital signature from a trusted certificate covering the relevant version",
    "a known-good hash from the issuing system or an immutable archive",
    "the source system's audit log or version history",
    "an independently obtained copy from the issuer",
    "internal metadata and structure (what this report analyses)",
]


def _count(findings: list[dict[str, Any]]) -> Counter:
    return Counter(f["severity"] for f in findings)


def _effective(f: dict[str, Any]) -> str:
    sev = f["severity"]
    if f["confidence"] == "low" and sev != "info":
        return SEVERITY_ORDER[SEVERITY_ORDER.index(sev) - 1]
    return sev


def _highlight(f: dict[str, Any]) -> str | None:
    """One line of the most decisive evidence for a finding."""
    ev = f.get("evidence") or {}
    if f["id"] == "revisions.content-changed":
        removed = [e["text"] for e in ev.get("text_removed", [])][:2]
        added = [e["text"] for e in ev.get("text_added", [])][:2]
        if removed or added:
            parts = []
            if removed:
                parts.append("removed: " + " / ".join(f'"{t}"' for t in removed))
            if added:
                parts.append("added: " + " / ".join(f'"{t}"' for t in added))
            return "; ".join(parts)
        return f"{ev.get('objects_changed', 0)} object(s) changed ({', '.join(ev.get('changed_roles', {}))})"
    if f["id"].startswith("signature.") and ev.get("summary"):
        return f"pyHanko: {ev['summary']}"
    if f["id"] == "signature.bytes-after-last-signature":
        return f"signed up to byte {ev.get('last_signed_end', 0):,} of {ev.get('file_size', 0):,}"
    if f["id"] == "metadata.editor-tool":
        return "tool(s): " + ", ".join(ev.get("tools", []))
    if f["id"] in ("metadata.modified-before-created", "metadata.info-xmp-date-mismatch"):
        return f"difference {ev.get('difference')}"
    if f["id"] == "office.tracked-changes":
        def strip(xs):
            return [x.split(": ", 1)[-1] for x in xs[:2]]
        parts = []
        if ev.get("deleted_text"):
            parts.append("deleted: " + " / ".join(f'"{t}"' for t in strip(ev["deleted_text"])))
        if ev.get("inserted_text"):
            parts.append("inserted: " + " / ".join(f'"{t}"' for t in strip(ev["inserted_text"])))
        if ev.get("authors"):
            parts.append("by " + ", ".join(ev["authors"][:3]))
        return "; ".join(parts) or None
    if f["id"] == "office.hidden-text" and ev.get("text"):
        return "hidden: " + " / ".join(f'"{t.split(": ", 1)[-1]}"' for t in ev["text"][:2])
    if ev.get("relationships"):
        return "targets: " + ", ".join(r.get("target", "") for r in ev["relationships"][:3])
    for key in ("files", "tools", "layers", "uris", "sheets", "parts"):
        if ev.get(key):
            vals = ev[key]
            return f"{key}: " + ", ".join(str(v) for v in vals[:3]) + (" ..." if len(vals) > 3 else "")
    if ev.get("pages"):
        return "pages: " + ", ".join(str(p.get("page")) for p in ev["pages"][:5])
    return None


def _profile(r: dict[str, Any]) -> str:
    facts = r.get("facts", {})
    if r["file"].get("format") == "ooxml":
        return _office_profile(r)
    if r["file"].get("format") == "ole":
        return "Legacy binary Office file (OLE2); only basic checks were possible."
    st, rev, sig, fp = (facts.get(k, {}) for k in ("structure", "revisions", "signatures", "fingerprint"))
    pages = st.get("pages", "?")
    origin = fp.get("producer_family") or (fp.get("producer") or "unknown software")
    updates = rev.get("incremental_updates", 0)
    parts = [f"{pages}-page PDF {st.get('pdf_version', '')} produced by {origin}".replace("  ", " ")]
    parts.append("no later edits appended" if not updates else f"{updates} later edit(s) appended to the file")
    n_sig = sig.get("signature_count", 0)
    if n_sig:
        validated = sig.get("validation") or []
        intact = sum(1 for v in validated if v.get("intact"))
        text = (f"{n_sig} signature(s), {intact} with the signed bytes verified intact" if validated
                else f"{n_sig} signature(s), not cryptographically verified")
        if any(f["id"] == "signature.bytes-after-last-signature" for f in r.get("findings", [])):
            text += ", but data was added after the last signature"
        parts.append(text)
    else:
        parts.append("not digitally signed")
    return "; ".join(parts) + "."


def _office_profile(r: dict[str, Any]) -> str:
    facts = r.get("facts", {})
    kind = (r["file"].get("kind") or "office").upper()
    meta = facts.get("office_metadata", {})
    app = meta.get("app", {})
    core = meta.get("core", {})
    content = facts.get("office_content", {})
    parts = [f"{kind} document produced by {app.get('Application') or 'unknown software'}"
             + (f" {app['AppVersion']}" if app.get("AppVersion") else "")]
    who = core.get("creator")
    last = core.get("lastModifiedBy")
    if who or last:
        parts.append(f"author '{who or '-'}', last saved by '{last or '-'}'")
    if core.get("created") or core.get("modified"):
        parts.append(f"created {core.get('created', '?')}, modified {core.get('modified', '?')}")
    rev = content.get("tracked_insertions", 0) + content.get("tracked_deletions", 0)
    parts.append(f"{rev} pending tracked change(s)" if rev else "no pending tracked changes")
    parts.append("contains macros" if facts.get("office_active", {}).get("macros") else "no macros")
    return "; ".join(parts) + "."


def _ruled_out(r: dict[str, Any]) -> list[str]:
    if r["file"].get("format") in ("ooxml", "ole"):
        return _office_ruled_out(r)
    ids = {f["id"] for f in r["findings"]}
    cats = {f["category"] for f in r["findings"] if f["severity"] != "info"}
    facts = r.get("facts", {})
    ran = _completed_analysers(r)
    out = []
    history_uncertain = ids & {"structure.xref-chain-broken", "structure.unlinked-revision",
                               "structure.extra-eof-markers"}
    if "revisions" in ran and not history_uncertain and not any(
            i.startswith("revisions.") and i not in ("revisions.signature-update", "revisions.metadata-update")
            for i in ids):
        out.append("No page content was changed through appended edits.")
    if ("signatures" in ran and facts.get("signatures", {}).get("signature_count") and
            not any(i in ids for i in SIGNATURE_DOUBTS)):
        out.append("All validated signatures are cryptographically intact.")
    if "content" in ran and "content" not in cats:
        out.append("No hidden text, print-only annotations or hidden layers.")
    if "active_content" in ran and "active-content" not in cats:
        out.append("No JavaScript, launch actions, form submission or suspicious attachments.")
    if "metadata" in ran and "metadata" not in cats:
        out.append("Metadata dates and producer information are consistent.")
    if "structure" in ran and "structure" not in cats:
        out.append("File structure is sound: no appended or prepended data, and no repairs needed.")
    return out


SIGNATURE_DOUBTS = ("signature.broken", "signature.disallowed-modification", "signature.malformed-byterange",
                    "signature.not-validated", "signature.unparseable", "signature.validation-error",
                    "signature.validators-disagree", "pdfsig.integrity-failure", "pdfsig.integrity-unknown")


def _completed_analysers(r: dict[str, Any]) -> set[str]:
    """Analysers that produced facts and reported no error. Only their areas can be ruled out."""
    failed = {e.get("analyzer") for e in r.get("errors", [])}
    return {name for name in r.get("facts", {}) if name not in failed}


def _office_ruled_out(r: dict[str, Any]) -> list[str]:
    if r["file"].get("format") == "ole":
        return []
    ids = {f["id"] for f in r["findings"]}
    cats = {f["category"] for f in r["findings"] if f["severity"] != "info"}
    ran = _completed_analysers(r)
    out = []
    if "office_content" in ran and "office.tracked-changes" not in ids:
        out.append("No pending tracked changes (no deleted text left in the file).")
    if "office_content" in ran and "content" not in cats:
        out.append("No hidden text, hidden or very-hidden sheets, or hidden slides.")
    if "office_active" in ran and "active-content" not in cats:
        out.append("No macros, DDE fields, remote templates, external content or embedded objects.")
    if "office_metadata" in ran and "metadata" not in cats:
        out.append("Document properties (dates, editing time) are consistent.")
    if "office_container" in ran and "structure" not in cats:
        out.append("Package structure is sound: consistent manifest, no duplicate or disguised parts.")
    return out


def _limitations(r: dict[str, Any]) -> list[str]:
    out = []
    if not r["verdict"].get("complete", True):
        failed = ", ".join(e["analyzer"] for e in r.get("errors", []))
        out.append(f"Analysis incomplete: {failed} could not run. Absent findings from these checks are not a clean result.")
    ids = {f["id"] for f in r["findings"]}
    if ids & {"signature.not-validated", "signature.validation-error", "signature.unparseable",
              "pdfsig.integrity-unknown"}:
        out.append("Some signatures could not be verified cryptographically.")
    if "analysis.objects-truncated" in ids or r.get("facts", {}).get("content", {}).get("pages_truncated"):
        out.append("Very large document: some objects or pages were outside the configured scan limits.")
    if r.get("facts", {}).get("revisions", {}).get("revisions_skipped"):
        out.append("Older revisions beyond --max-revisions were not compared.")
    if r.get("facts", {}).get("signatures", {}).get("signature_count") and not r["tool"].get("pyhanko"):
        out.append("pyHanko is not installed, so signatures were checked structurally only.")
    if "office.xml-signature" in ids:
        out.append("Office XML signatures were detected but not cryptographically validated by this tool.")
    if r.get("facts", {}).get("office_container", {}).get("parts_not_parsed"):
        out.append("Some package parts could not be parsed safely and were skipped.")
    out.append("Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.")
    return out


def summarize(r: dict[str, Any]) -> dict[str, Any]:
    """Build the summary for one report dictionary."""
    findings = r["findings"]
    attention = [f for f in findings if _effective(f) in ATTENTION]
    counts = _count(attention)
    name = r["file"]["name"]
    label = r["verdict"]["label"]
    if attention:
        breakdown = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts.get(s))
        headline = f"{name}: {label} - {len(attention)} finding(s) need attention ({breakdown})."
    else:
        minor = sum(1 for f in findings if _effective(f) == "low")
        headline = (f"{name}: {label} - no significant findings"
                    + (f" ({minor} minor anomaly/anomalies noted)." if minor else "."))

    key = []
    for f in attention[:6]:
        item = {"id": f["id"], "severity": _effective(f), "title": f["title"]}
        h = _highlight(f)
        if h:
            item["evidence"] = h
        if f.get("benign_explanations"):
            item["could_be_benign_if"] = f["benign_explanations"][0]
        key.append(item)

    actions: list[str] = []
    for f in attention:
        a = ACTIONS.get(f["id"])
        if a and a not in actions:
            actions.append(a)
    if not actions:
        actions.append("No action required from the structural analysis. Apply normal business verification "
                       "(check with the issuer, and compare with known genuine documents) as usual.")
    else:
        actions = actions[:5]
        actions.append("To settle the question, use a stronger source than this analysis, in this order: "
                       + "; ".join(VERIFICATION_HIERARCHY[:4]) + ".")

    return {
        "headline": headline,
        "verdict": label,
        "level": r["verdict"]["level"],
        "complete": r["verdict"].get("complete", True),
        "document": _profile(r),
        "key_findings": key,
        "ruled_out": _ruled_out(r),
        "recommended_actions": actions,
        "limitations": _limitations(r),
        "sha256": r["file"]["sha256"],
    }


def summary_markdown(s: dict[str, Any], heading: str = "## Summary") -> str:
    out = [heading, "", f"**{s['headline']}**", "", s["document"], ""]
    if s["key_findings"]:
        out += ["**Key findings**", ""]
        for k in s["key_findings"]:
            line = f"- [{k['severity'].upper()}] {k['title']}"
            if k.get("evidence"):
                line += f": {k['evidence']}"
            if k.get("could_be_benign_if"):
                b = k["could_be_benign_if"]
                line += f" _(benign if: {b[:1].lower() + b[1:]})_"
            out.append(line)
        out.append("")
    if s["ruled_out"]:
        out += ["**Checked and found in order**", ""] + [f"- {x}" for x in s["ruled_out"]] + [""]
    out += ["**Recommended next steps**", ""] + [f"{i}. {a}" for i, a in enumerate(s["recommended_actions"], 1)] + [""]
    out += ["**Limitations**", ""] + [f"- {x}" for x in s["limitations"]] + [""]
    return "\n".join(out)


def batch_summary(reports: list[dict[str, Any]], failures: list[dict[str, str]] | None = None) -> dict[str, Any]:
    failures = failures or []
    per = [(r, r.get("summary") or summarize(r)) for r in reports]
    verdicts = Counter(s["verdict"] for _, s in per)
    order = {lvl: i for i, lvl in enumerate(SEVERITY_ORDER)}
    needing = sorted((x for x in per if x[1]["level"] in ATTENTION),
                     key=lambda x: order[x[1]["level"]], reverse=True)
    pipelines = Counter((r.get("facts", {}).get("fingerprint", {}) or {}).get("pipeline_hash") for r, _ in per)
    total = len(reports) + len(failures)
    # an incomplete analysis without significant findings is not a clean result; count it apart
    incomplete = [r for r, s in per if s["level"] not in ATTENTION and not r["verdict"].get("complete", True)]
    headline = (f"{total} document(s) submitted: {len(needing)} need attention, "
                f"{len(reports) - len(needing) - len(incomplete)} without significant findings"
                + (f", {len(incomplete)} incomplete (some checks failed)" if incomplete else "")
                + (f", {len(failures)} could not be analysed" if failures else "") + ".")
    return {
        "headline": headline,
        "verdict_counts": dict(verdicts),
        "needs_attention": [{"file": r["file"]["name"], "verdict": s["verdict"],
                             "reason": s["key_findings"][0]["title"] if s["key_findings"] else ""}
                            for r, s in needing],
        "not_analysed": failures,
        "distinct_pipelines": len([p for p in pipelines if p]),
    }


def batch_summary_markdown(b: dict[str, Any]) -> str:
    out = ["## Executive summary", "", f"**{b['headline']}**", ""]
    if b["verdict_counts"]:
        out.append("Verdicts: " + ", ".join(f"`{k}` x{v}" for k, v in sorted(b["verdict_counts"].items())))
        out.append("")
    if b["needs_attention"]:
        out += ["**Needs attention (most severe first)**", ""]
        out += [f"- {x['file']}: `{x['verdict']}` - {x['reason']}" for x in b["needs_attention"]]
        out.append("")
    if b["not_analysed"]:
        out += ["**Not analysed**", ""] + [f"- {x['file']}: {x['error']}" for x in b["not_analysed"]] + [""]
    out.append(f"The documents come from {b['distinct_pipelines']} distinct production pipeline(s). Documents that "
               "claim the same issuer but fall into different pipelines deserve a closer look.")
    out.append("")
    return "\n".join(out)
