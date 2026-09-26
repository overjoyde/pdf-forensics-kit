"""pdf-forensics-kit: explainable, signature-aware PDF tampering and provenance analysis."""

__version__ = "0.3.0"

from pdfforensics.engine import analyze_file  # noqa: E402

__all__ = ["analyze_file", "__version__"]
