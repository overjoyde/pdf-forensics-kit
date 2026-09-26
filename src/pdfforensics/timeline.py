"""Edit timeline: what changed, when, and to what, assembled from the other analysers' facts.

Times written inside a file are claims made by the software that wrote them and can be forged.
Every event therefore names the source of its time and how much that source proves:

- claimed: written by the editing software (Info /ModDate, XMP, signature /M, Word w:date)
- signed: inside the signed attributes of a signature (signingTime)
- timestamped: in an RFC 3161 timestamp token issued by a timestamp authority
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import iso, parse_xmp_date

CLAIMED, SIGNED, TIMESTAMPED = "claimed", "signed", "timestamped"
TOLERANCE = timedelta(minutes=2)


def _event(kind: str, what: str, *, when: str | None = None, source: str = "", evidence: str | None = None,
           before: list[str] | None = None, after: list[str] | None = None, who: str = "",
           revision: int | None = None, after_signing: bool = False) -> dict[str, Any]:
    before, after = before or [], after or []
    return {"kind": kind, "what": what, "when": when, "time_source": source if when else "",
            "time_evidence": evidence if when else None, "before": before, "after": after,
            "paired": bool(before) and len(before) == len(after), "who": who,
            "revision": revision, "after_signing": after_signing}


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _aware(d: datetime | None) -> datetime | None:
    return d if d is not None and d.tzinfo is not None else None


def _revision_time(t: dict[str, Any]) -> tuple[str | None, str]:
    n = t.get("revision")
    if t.get("info_mod"):
        return t["info_mod"], f"Info /ModDate of revision {n}"
    if t.get("xmp_modify"):
        return t["xmp_modify"], f"XMP ModifyDate of revision {n}"
    return None, ""


def _pdf_events(facts: dict[str, Any]) -> list[dict[str, Any]]:
    rev = facts.get("revisions", {})
    times = {t["revision"]: t for t in rev.get("revision_times", [])}
    sig = facts.get("signatures", {})
    signed_ends = [c["signed_end"] for c in sig.get("signatures", []) if "signed_end" in c]
    last_signed = max(signed_ends) if signed_ends else None
    events: list[dict[str, Any]] = []

    first = times.get(1)
    if first:
        created = first.get("info_created") or first.get("info_mod") or first.get("xmp_modify")
        events.append(_event("created", "Original version (revision 1)", when=created,
                             source="Info /CreationDate of revision 1" if first.get("info_created")
                             else _revision_time(first)[1], evidence=CLAIMED, who=first.get("producer", ""),
                             revision=1))

    for u in rev.get("updates", []):
        n = u["revision"]
        when, source = _revision_time(times.get(n, {}))
        who = times.get(n, {}).get("producer", "")
        if "error" in u:
            events.append(_event("unreadable-revision", f"Revision {n} could not be reconstructed",
                                 when=when, source=source, evidence=CLAIMED, revision=n))
            continue
        after_signing = last_signed is not None and u["end"] > last_signed + 4
        diff = u.get("text_diff") or {}
        pages = sorted({e["page"] for e in diff.get("added", []) + diff.get("removed", [])})
        for p in pages:
            events.append(_event(
                "content-change", f"Text on page {p} changed in revision {n}", when=when, source=source,
                evidence=CLAIMED, who=who, revision=n, after_signing=after_signing,
                before=[e["text"] for e in diff.get("removed", []) if e["page"] == p],
                after=[e["text"] for e in diff.get("added", []) if e["page"] == p]))
        if not pages:
            roles = ", ".join(sorted(u.get("changed_roles", {}))) or "objects"
            label = "signature added" if u.get("signing_revision") else f"{roles} changed, no visible text change"
            events.append(_event("revision", f"Revision {n}: {label}", when=when, source=source,
                                 evidence=CLAIMED, who=who, revision=n, after_signing=after_signing))

    ends = {t["revision"]: t["end"] for t in rev.get("revision_times", [])}
    for v in sig.get("validation", []):
        field = v.get("field") or "?"
        n = next((k for k, e in ends.items() if v.get("signed_end") is not None
                  and abs(e - v["signed_end"]) <= 4), None)
        if v.get("kind") == "document-timestamp":
            events.append(_event("timestamp", f"Document timestamp '{field}'", when=v.get("timestamp_time"),
                                 source="RFC 3161 timestamp token", evidence=TIMESTAMPED, revision=n))
        elif v.get("signature_timestamp_time"):
            events.append(_event("signature", f"Signature '{field}'", when=v["signature_timestamp_time"],
                                 source="RFC 3161 timestamp on the signature", evidence=TIMESTAMPED,
                                 who=v.get("signer", ""), revision=n))
        elif v.get("signer_reported_time"):
            events.append(_event("signature", f"Signature '{field}'", when=v["signer_reported_time"],
                                 source="signingTime attribute inside the signature", evidence=SIGNED,
                                 who=v.get("signer", ""), revision=n))
    if not sig.get("validation"):
        for c in sig.get("signatures", []):
            events.append(_event("signature", f"Signature {c.get('object', '?')}",
                                 when=c.get("signing_time_claimed"), source="/M in the signature dictionary",
                                 evidence=CLAIMED, who=c.get("signer_name", "")))

    for h in (facts.get("metadata", {}).get("xmp") or {}).get("history", []):
        what = f"XMP history: {h.get('action') or 'event'}" + (f" ({h['changed']})" if h.get("changed") else "")
        events.append(_event("save-event", what, when=iso(parse_xmp_date(h.get("when", ""))),
                             source="XMP stEvt:when", evidence=CLAIMED, who=h.get("softwareAgent", "")))
    return events


def _word_events(facts: dict[str, Any]) -> list[dict[str, Any]]:
    changes = facts.get("office_content", {}).get("tracked_changes", [])
    events: list[dict[str, Any]] = []
    i = 0
    while i < len(changes):
        c = changes[i]
        nxt = changes[i + 1] if i + 1 < len(changes) else None
        when = iso(parse_xmp_date(c.get("date", "")))
        common = {"when": when, "source": "w:date on the tracked change", "evidence": CLAIMED,
                  "who": c.get("author", "")}
        if (c["type"] == "del" and nxt and nxt["type"] == "ins" and nxt.get("author") == c.get("author")
                and nxt.get("date") == c.get("date")):
            events.append(_event("tracked-change", f"Tracked change in {c['part']}", before=[c["text"]],
                                 after=[nxt["text"]], **common))
            i += 2
            continue
        label = "Tracked deletion" if c["type"] == "del" else "Tracked insertion"
        events.append(_event("tracked-change", f"{label} in {c['part']}",
                             before=[c["text"]] if c["type"] == "del" else [],
                             after=[c["text"]] if c["type"] == "ins" else [], **common))
        i += 1
    return events


def _sort(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Timed events by time (UTC-normalised; naive times as UTC), then untimed ones in their original order."""
    def key(e: dict[str, Any]) -> datetime:
        d = _dt(e["when"])
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    timed = [e for e in events if _dt(e["when"])]
    untimed = [e for e in events if not _dt(e["when"])]
    return sorted(timed, key=key) + untimed


def _inconsistencies(events: list[dict[str, Any]], revision_times: list[dict[str, Any]]) -> list[dict[str, Any]]:
    problems = []
    revs: dict[int, datetime] = {}
    for t in revision_times:  # the save time each revision claims, revision 1 included
        d = _aware(_dt(_revision_time(t)[0]))
        if d:
            revs[t["revision"]] = d
    ordered = sorted(revs.items())
    for (ra, da), (rb, db) in zip(ordered, ordered[1:]):
        if db < da - TOLERANCE:
            problems.append({"issue": f"revision {rb} claims an earlier time than revision {ra}",
                             "earlier_revision": [ra, da.isoformat()], "later_revision": [rb, db.isoformat()]})
    for e in events:
        d = _aware(_dt(e["when"]))
        if e["time_evidence"] != TIMESTAMPED or not d or e["revision"] is None:
            continue
        for r, rd in revs.items():
            if r <= e["revision"] and rd > d + TOLERANCE:
                problems.append({"issue": f"revision {r} claims a time after the trusted timestamp that covers it",
                                 "revision": [r, rd.isoformat()], "timestamp": d.isoformat()})
    return problems


def build(facts: dict[str, Any], fmt: str) -> AnalyzerResult:
    res = AnalyzerResult(name="timeline")
    events = _pdf_events(facts) if fmt == "pdf" else _word_events(facts) if fmt == "ooxml" else []
    events = _sort(events)
    res.facts["events"] = events
    res.facts["untimed"] = sum(1 for e in events if not e["when"])
    revision_times = facts.get("revisions", {}).get("revision_times", []) if fmt == "pdf" else []
    problems = _inconsistencies(events, revision_times)
    if problems:
        res.findings.append(Finding(
            id="timeline.inconsistent-times", title="Times recorded in the file contradict each other",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, category="metadata",
            explanation=("Save times written into the file do not follow the order of the revisions, or a claimed "
                         "time lies after a trusted timestamp that covers it. Clocks can be wrong, but this is also "
                         "what backdating an edit looks like."),
            evidence={"problems": problems[:20]},
            benign_explanations=["Wrong system clock on the editing computer",
                                 "Software that copies dates from a template"]))
    return res
