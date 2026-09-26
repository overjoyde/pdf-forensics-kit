"""Analysers. Each exposes ``analyze(doc) -> AnalyzerResult``."""

from pdfforensics.analyzers import (
    active_content,
    content,
    fingerprint,
    metadata,
    pdfsig,
    revisions,
    signatures,
    structure,
)

# PDF analysers, in run order (pdfsig must follow signatures: it cross-checks pyHanko's result)
ALL = [
    ("structure", structure.analyze),
    ("revisions", revisions.analyze),
    ("signatures", signatures.analyze),
    ("pdfsig", pdfsig.analyze),
    ("metadata", metadata.analyze),
    ("content", content.analyze),
    ("active_content", active_content.analyze),
    ("fingerprint", fingerprint.analyze),
]
