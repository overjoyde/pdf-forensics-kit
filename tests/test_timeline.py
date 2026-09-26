"""Edit timeline: what changed, when, and to what."""

import importlib

import pytest

import pdfgen
from conftest import finding, ids


def _have_pyhanko() -> bool:
    try:
        importlib.import_module("pyhanko.sign")
        return True
    except ImportError:
        return False


needs_pyhanko = pytest.mark.skipif(not _have_pyhanko(), reason="pyHanko not installed")


@needs_pyhanko
def test_signature_and_timestamp_times_are_recorded(analyze):
    r = analyze(pdfgen.document_timestamp(pdfgen.sign(pdfgen.build())))
    by_kind = {v.get("kind", "signature"): v for v in r["facts"]["signatures"]["validation"]}
    assert by_kind["signature"]["signer_reported_time"].startswith("20")
    assert by_kind["signature"]["signed_end"] > 0
    assert by_kind["document-timestamp"]["timestamp_time"].startswith("20")
