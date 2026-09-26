"""The bank-statement example case must keep producing the documented verdicts."""

import importlib.util
import sys
from pathlib import Path

import pytest

from conftest import ids
from pdfforensics.engine import analyze_file

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("make_bank_statements", ROOT / "examples" / "make_bank_statements.py")
mbs = importlib.util.module_from_spec(spec)
sys.modules["make_bank_statements"] = mbs
spec.loader.exec_module(mbs)


def _have_pyhanko() -> bool:
    try:
        import pyhanko.sign  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    out = tmp_path_factory.mktemp("bank")
    paths = mbs.generate(out, with_signatures=_have_pyhanko())
    return {name: analyze_file(p).to_dict() for name, p in paths.items()}


EXPECTED = {
    "01_original.pdf": ("no-indicators", set()),
    "03_edited_in_acrobat.pdf": ("significant-indicators",
                                 {"revisions.content-changed", "metadata.info-xmp-date-mismatch",
                                  "metadata.producer-mismatch"}),
    "04_edited_online_editor.pdf": ("review-recommended", {"metadata.editor-tool", "content.invisible-text"}),
    "06_transactions_export.xlsx": ("review-recommended", {"office.very-hidden-sheets"}),
}
SIGNED = {
    "02_original_signed.pdf": ("no-indicators", {"signature.intact", "revisions.signature-update"}),
    "05_signed_then_edited.pdf": ("strong-indicators",
                                  {"revisions.content-changed", "signature.disallowed-modification"}),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_unsigned_variants(case, name):
    label, must = EXPECTED[name]
    r = case[name]
    assert r["verdict"]["label"] == label, [(f["id"], f["severity"]) for f in r["findings"]]
    assert must <= ids(r)


@pytest.mark.skipif(not _have_pyhanko(), reason="pyHanko needed to build the signed variants")
@pytest.mark.parametrize("name", sorted(SIGNED))
def test_signed_variants(case, name):
    label, must = SIGNED[name]
    r = case[name]
    assert r["verdict"]["label"] == label, [(f["id"], f["severity"]) for f in r["findings"]]
    assert must <= ids(r)


def test_forged_salary_is_quoted_as_evidence(case):
    f = next(f for f in case["03_edited_in_acrobat.pdf"]["findings"] if f["id"] == "revisions.content-changed")
    removed = " ".join(e["text"] for e in f["evidence"]["text_removed"])
    added = " ".join(e["text"] for e in f["evidence"]["text_added"])
    assert "32 450,00" in removed and "52 450,00" in added


def test_statement_arithmetic_is_consistent():
    """The forgery is 'good': balances still add up, so only forensics can tell."""
    for salary in (mbs.SALARY_ORIGINAL, mbs.SALARY_FAKE):
        rows = mbs.rows(salary)
        assert round(mbs.OPENING + sum(r[2] for r in rows), 2) == rows[-1][3]
