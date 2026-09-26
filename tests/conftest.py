import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from pdfforensics.engine import analyze_file  # noqa: E402


@pytest.fixture
def analyze(tmp_path):
    """Write bytes to a temp file and return the report as a dict."""

    def _run(data: bytes, name: str = "doc.pdf") -> dict:
        p = tmp_path / name
        p.write_bytes(data)
        return analyze_file(p).to_dict()

    return _run


def ids(report: dict) -> set[str]:
    return {f["id"] for f in report["findings"]}


def finding(report: dict, fid: str) -> dict:
    matches = [f for f in report["findings"] if f["id"] == fid]
    assert matches, f"{fid} not in {sorted(ids(report))}"
    return matches[0]
