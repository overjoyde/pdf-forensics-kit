"""Verdict rule. Deliberately simple and printed in every report.

1. A finding's *effective severity* is its severity, lowered by one step if its confidence is low.
2. The verdict level is the highest effective severity among all findings.
3. If any analyser failed, the verdict is marked incomplete. A failed check never counts as "clean".
"""

from __future__ import annotations

from typing import Any

from pdfforensics.model import Confidence, Finding, Severity

RULE = (
    "Effective severity = severity, one step lower when confidence is low. "
    "Verdict = highest effective severity across findings. "
    "Incomplete if any analyser failed."
)

LABELS = {
    Severity.INFO: ("no-indicators", "No indicators of manipulation were found in the checks performed."),
    Severity.LOW: ("minor-anomalies", "Minor anomalies that are usually benign; review the evidence if the document is important."),
    Severity.MEDIUM: ("review-recommended", "Anomalies that need an explanation before relying on the document."),
    Severity.HIGH: ("significant-indicators", "Significant indicators of post-creation modification or hidden content."),
    Severity.CRITICAL: ("strong-indicators", "Strong indicators of manipulation, for example content changed after signing or a broken signature."),
}


def effective(f: Finding) -> Severity:
    if f.confidence == Confidence.LOW and f.severity > Severity.INFO:
        return Severity(f.severity - 1)
    return f.severity


def verdict(findings: list[Finding], errors: list[dict[str, str]]) -> dict[str, Any]:
    level = max((effective(f) for f in findings), default=Severity.INFO)
    label, summary = LABELS[level]
    counts = {sev.label: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.label] += 1
    top = sorted(findings, key=lambda f: (effective(f), f.confidence), reverse=True)
    return {
        "level": level.label,
        "label": label,
        "summary": summary,
        "complete": not errors,
        "severity_counts": counts,
        "top_findings": [f.id for f in top if effective(f) >= Severity.MEDIUM][:10],
        "rule": RULE,
        "disclaimer": ("Structural analysis only. It cannot prove that the content is true or that a document is "
                       "genuine. A clean result is not proof of authenticity."),
    }
