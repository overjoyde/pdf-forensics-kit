"""A check that failed or could not decide must never be presented as a clean result."""

import importlib

import pytest

import pdfgen
from conftest import finding, ids
from pdfforensics import analyzers, render
from pdfforensics.analyzers import pdfsig
from pdfforensics.cli import main


def _have_pyhanko() -> bool:
    try:
        importlib.import_module("pyhanko.sign")
        return True
    except ImportError:
        return False


needs_pyhanko = pytest.mark.skipif(not _have_pyhanko(), reason="pyHanko not installed")


@pytest.fixture
def crashing(monkeypatch):
    def boom(doc):
        raise RuntimeError("simulated analyser failure")
    patched = [(n, boom if n in ("revisions", "active_content") else f) for n, f in analyzers.ALL]
    monkeypatch.setattr(analyzers, "ALL", patched)


def test_failed_analysers_are_not_listed_as_checked(analyze, crashing):
    r = analyze(pdfgen.build())
    assert r["verdict"]["complete"] is False
    ruled_out = r["summary"]["ruled_out"]
    assert "No page content was changed through appended edits." not in ruled_out
    assert "No JavaScript, launch actions, form submission or suspicious attachments." not in ruled_out
    assert "Metadata dates and producer information are consistent." in ruled_out


def test_batch_marks_incomplete_reports(analyze, crashing):
    r = analyze(pdfgen.build())
    md = render.batch_markdown([r, r], [])
    assert "`no-indicators` (incomplete)" in md
    assert "2 incomplete" in md
    assert "0 without significant findings" in md


def test_fail_on_triggers_for_incomplete_analysis(tmp_path, crashing, capsys):
    p = tmp_path / "doc.pdf"
    p.write_bytes(pdfgen.build())
    assert main(["analyze", str(p), "--no-prompt", "--no-external-tools", "--fail-on", "critical"]) == 1


def test_fail_on_triggers_when_a_file_could_not_be_analysed(tmp_path, capsys):
    good = tmp_path / "good.pdf"
    good.write_bytes(pdfgen.build())
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(b"%PDF-1.4\nnot really a pdf")
    assert main(["analyze", str(good), str(bad), "--no-prompt", "--no-external-tools", "--fail-on", "critical"]) == 1


@needs_pyhanko
def test_unparseable_signature_container_is_high(analyze):
    r = analyze(pdfgen.corrupt_first_signature(pdfgen.sign(pdfgen.build())))
    f = finding(r, "signature.unparseable")
    assert f["severity"] == "high"
    assert r["verdict"]["level"] in ("high", "critical")
    assert "All validated signatures are cryptographically intact." not in r["summary"]["ruled_out"]


@needs_pyhanko
def test_one_bad_signature_does_not_hide_the_others(analyze):
    two = pdfgen.sign(pdfgen.sign(pdfgen.build(), "Sig1"), "Sig2")
    r = analyze(pdfgen.corrupt_first_signature(two))
    fields = {v.get("field"): v for v in r["facts"]["signatures"]["validation"]}
    assert "error" in fields["Sig1"]
    assert "intact" in fields["Sig2"]


@needs_pyhanko
def test_validation_error_is_not_downgraded(analyze, monkeypatch):
    from pdfforensics.analyzers import signatures

    def fail(*a, **k):
        raise RuntimeError("validator exploded")
    monkeypatch.setattr(signatures, "validate_pdf_signature", fail)
    r = analyze(pdfgen.sign(pdfgen.build()))
    assert finding(r, "signature.validation-error")["confidence"] != "low"
    assert r["verdict"]["level"] == "medium"
    assert "All validated signatures are cryptographically intact." not in r["summary"]["ruled_out"]


def test_pdfsig_unknown_integrity_is_reported(analyze, monkeypatch):
    monkeypatch.setattr(pdfsig, "find_pdfsig", lambda: "/usr/bin/pdfsig")
    monkeypatch.setattr(pdfsig, "pdfsig_version", lambda exe: "test")
    monkeypatch.setattr(pdfsig, "_has_signature_dict", lambda pdf: True)
    monkeypatch.setattr(pdfsig, "run_pdfsig", lambda *a, **k: {
        "status": "ok", "return_code": 1, "presence": "present",
        "signatures": [{"index": 1, "integrity": "unknown", "trust": "not-checked", "field": "Sig1",
                        "integrity_text": "Signature has not yet been verified."}]})
    r = analyze(pdfgen.build())
    assert "pdfsig.integrity-unknown" in ids(r)
