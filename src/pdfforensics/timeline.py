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
NAIVE_TOLERANCE = timedelta(hours=14)  # widest UTC offset spread when a date has no timezone


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


def _own_times(revision_times: list[dict[str, Any]]) -> dict[int, tuple[str | None, str]]:
    """The save time each revision wrote itself. An update that leaves /Info and XMP alone inherits the
    earlier values; those are not its own save time, so it gets none."""
    own: dict[int, tuple[str | None, str]] = {}
    prev: dict[str, Any] | None = None
    for t in sorted(revision_times, key=lambda x: x["revision"]):
        n = t["revision"]
        if prev is None or (t.get("info_mod") and t.get("info_mod") != prev.get("info_mod")):
            own[n] = _revision_time(t)
        elif t.get("xmp_modify") and t.get("xmp_modify") != prev.get("xmp_modify"):
            own[n] = (t["xmp_modify"], f"XMP ModifyDate of revision {n}")
        else:
            own[n] = (None, "")
        prev = t
    return own


def _pdf_events(facts: dict[str, Any]) -> list[dict[str, Any]]:
    rev = facts.get("revisions", {})
    times = {t["revision"]: t for t in rev.get("revision_times", [])}
    own = _own_times(rev.get("revision_times", []))
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
        when, source = own.get(n, (None, ""))
        unstamped = "" if when else " (no save time written in this revision)"
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
                "content-change", f"Text on page {p} changed in revision {n}{unstamped}", when=when, source=source,
                evidence=CLAIMED, who=who, revision=n, after_signing=after_signing,
                before=[e["text"] for e in diff.get("removed", []) if e["page"] == p],
                after=[e["text"] for e in diff.get("added", []) if e["page"] == p]))
        if not pages:
            roles = ", ".join(sorted(u.get("changed_roles", {}))) or "objects"
            label = "signature added" if u.get("signing_revision") else f"{roles} changed, no visible text change"
            events.append(_event("revision", f"Revision {n}: {label}{unstamped}", when=when, source=source,
                                 evidence=CLAIMED, who=who, revision=n, after_signing=after_signing))

    ends = {t["revision"]: t["end"] for t in rev.get("revision_times", [])}
    for v in sig.get("validation", []):
        field = v.get("field") or "?"
        n = next((k for k, e in ends.items() if v.get("signed_end") is not None
                  and abs(e - v["signed_end"]) <= 4), None)
        # a time is only as good as the cryptography around it: a broken signature vouches for nothing
        broken = v.get("intact") is False
        note = " (the signature does not match the file)" if broken else ""
        if v.get("kind") == "document-timestamp":
            events.append(_event("timestamp", f"Document timestamp '{field}'", when=v.get("timestamp_time"),
                                 source="RFC 3161 timestamp token" + note,
                                 evidence=CLAIMED if broken else TIMESTAMPED, revision=n))
        elif v.get("signature_timestamp_time"):
            events.append(_event("signature", f"Signature '{field}'", when=v["signature_timestamp_time"],
                                 source="RFC 3161 timestamp on the signature" + note,
                                 evidence=CLAIMED if broken else TIMESTAMPED, who=v.get("signer", ""), revision=n))
        elif v.get("signer_reported_time"):
            events.append(_event("signature", f"Signature '{field}'", when=v["signer_reported_time"],
                                 source="signingTime attribute inside the signature" + note,
                                 evidence=CLAIMED if broken else SIGNED, who=v.get("signer", ""), revision=n))
        else:
            claimed = next((c.get("signing_time_claimed") for c in sig.get("signatures", [])
                            if v.get("signed_end") is not None and c.get("signed_end") == v["signed_end"]), None)
            events.append(_event("signature", f"Signature '{field}'", when=claimed,
                                 source="/M in the signature dictionary", evidence=CLAIMED,
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
    """One event per run of consecutive tracked changes with the same author and date.

    Word splits text into runs at every formatting boundary, so one edit is often several w:del and w:ins
    elements. Their texts are joined, so the event reads as the whole deleted and inserted text.
    """
    changes = facts.get("office_content", {}).get("tracked_changes", [])
    groups: list[list[dict[str, str]]] = []
    for c in changes:
        if groups and groups[-1][0].get("author") == c.get("author") and groups[-1][0].get("date") == c.get("date"):
            groups[-1].append(c)
        else:
            groups.append([c])
    events: list[dict[str, Any]] = []
    for g in groups:
        first = g[0]
        deleted = " ".join(c["text"] for c in g if c["type"] == "del")
        inserted = " ".join(c["text"] for c in g if c["type"] == "ins")
        label = ("Tracked change" if deleted and inserted else
                 "Tracked deletion" if deleted else "Tracked insertion")
        events.append(_event("tracked-change", f"{label} in {first['part']}",
                             when=iso(parse_xmp_date(first.get("date", ""))),
                             source="w:date on the tracked change", evidence=CLAIMED, who=first.get("author", ""),
                             before=[deleted] if deleted else [], after=[inserted] if inserted else []))
    return events


def _sort(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order events the way the file proves them, then by time.

    The order of PDF revisions is fixed by the bytes; a time written into a revision is only a claim.
    Events tied to a revision therefore follow revision order (by time within a revision). Events without
    a revision (XMP history, Word tracked changes) follow by time, untimed ones last in their original order.
    """
    far = datetime.max.replace(tzinfo=timezone.utc)

    def when(e: dict[str, Any]) -> datetime:
        d = _dt(e["when"])
        if d is None:
            return far
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

    indexed = list(enumerate(events))
    by_revision = sorted((x for x in indexed if x[1]["revision"] is not None),
                         key=lambda x: (x[1]["revision"], when(x[1]), x[0]))
    others = sorted((x for x in indexed if x[1]["revision"] is None), key=lambda x: (when(x[1]), x[0]))
    return [e for _, e in by_revision + others]


def _utc(value: str | None) -> tuple[datetime | None, bool]:
    """(time as UTC-aware, whether the original had no timezone)."""
    d = _dt(value)
    if d is None:
        return None, False
    return (d, False) if d.tzinfo else (d.replace(tzinfo=timezone.utc), True)


def _inconsistencies(events: list[dict[str, Any]], revision_times: list[dict[str, Any]]) -> list[dict[str, Any]]:
    problems = []
    revs: dict[int, tuple[datetime, bool]] = {}
    for n, (when, _) in _own_times(revision_times).items():  # only times a revision wrote itself
        d, naive = _utc(when)
        if d:
            revs[n] = (d, naive)
    ordered = sorted(revs.items())
    for (ra, (da, na)), (rb, (db, nb)) in zip(ordered, ordered[1:]):
        slack = NAIVE_TOLERANCE if (na or nb) else TOLERANCE
        if db < da - slack:
            problems.append({"issue": f"revision {rb} claims an earlier time than revision {ra}",
                             "earlier_revision": [ra, da.isoformat()], "later_revision": [rb, db.isoformat()]})
    for e in events:
        d = _aware(_dt(e["when"]))
        if e["time_evidence"] != TIMESTAMPED or not d or e["revision"] is None:
            continue
        for r, (rd, naive) in revs.items():
            if r <= e["revision"] and rd > d + (NAIVE_TOLERANCE if naive else TOLERANCE):
                problems.append({"issue": f"revision {r} claims a time after the trusted timestamp that covers it",
                                 "revision": [r, rd.isoformat()], "timestamp": d.isoformat()})
    return problems


def build(facts: dict[str, Any], fmt: str) -> AnalyzerResult:
    res = AnalyzerResult(name="timeline")
    kind = facts.get("office_container", {}).get("kind")
    covered = fmt == "pdf" or (fmt == "ooxml" and kind == "docx")
    res.facts["covered"] = covered
    events = (_pdf_events(facts) if fmt == "pdf" else _word_events(facts)) if covered else []
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
