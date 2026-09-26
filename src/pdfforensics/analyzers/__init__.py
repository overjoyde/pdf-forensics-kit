"""Analysers. Each exposes ``analyze(doc) -> AnalyzerResult``."""

from pdfforensics.analyzers import (
    active_content,
    content,
    fingerprint,
    metadata,
    revisions,
    signatures,
    structure,
)

ALL = [
    ("structure", structure.analyze),
    ("revisions", revisions.analyze),
    ("signatures", signatures.analyze),
    ("metadata", metadata.analyze),
    ("content", content.analyze),
    ("active_content", active_content.analyze),
    ("fingerprint", fingerprint.analyze),
]
