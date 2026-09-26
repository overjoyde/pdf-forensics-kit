"""Core data model: findings and reports.

A *finding* is a single, explainable observation. Every finding carries the evidence it is
based on and, where relevant, the benign explanations an examiner should rule out. The
overall verdict is derived from findings by a documented rule (see ``scoring.py``), never
from hidden point totals.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    benign_explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["confidence"] = self.confidence.label
        return d


@dataclass
class AnalyzerResult:
    """Output of a single analyser: findings plus structured facts for the report."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Report:
    file: dict[str, Any]
    tool: dict[str, Any]
    verdict: dict[str, Any]
    findings: list[Finding]
    facts: dict[str, Any]
    errors: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "tool": self.tool,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "facts": self.facts,
            "errors": self.errors,
        }
