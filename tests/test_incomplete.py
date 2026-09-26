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


def test_fail_on_incomplete_triggers_for_incomplete_analysis(tmp_path, crashing, capsys):
    p = tmp_path / "doc.pdf"
    p.write_bytes(pdfgen.build())
    args = ["analyze", str(p), "--no-prompt", "--no-external-tools"]
    assert main(args + ["--fail-on", "critical"]) == 0          # unchanged behaviour
    assert main(args + ["--fail-on-incomplete"]) == 1


def test_fail_on_incomplete_triggers_when_a_file_could_not_be_analysed(tmp_path, capsys):
    good = tmp_path / "good.pdf"
    good.write_bytes(pdfgen.build())
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(b"%PDF-1.4\nnot really a pdf")
    args = ["analyze", str(good), str(bad), "--no-prompt", "--no-external-tools"]
    assert main(args + ["--fail-on", "critical"]) == 0
    assert main(args + ["--fail-on-incomplete"]) == 1


def test_fail_on_incomplete_passes_a_complete_clean_run(tmp_path, capsys):
    p = tmp_path / "doc.pdf"
    p.write_bytes(pdfgen.build())
    assert main(["analyze", str(p), "--no-prompt", "--no-external-tools", "--fail-on-incomplete"]) == 0


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
    r = analyze(pdfgen.corrupt_last_signature(two))
    fields = {v.get("field"): v for v in r["facts"]["signatures"]["validation"]}
    assert fields["Sig1"]["intact"] is True
    assert fields["Sig2"].get("unparseable") is True


@needs_pyhanko
@pytest.mark.parametrize("signed_first", [False, True], ids=["timestamp-only", "signature-then-timestamp"])
def test_document_timestamp_is_validated_not_flagged(analyze, signed_first):
    base = pdfgen.build()
    r = analyze(pdfgen.document_timestamp(pdfgen.sign(base) if signed_first else base))
    assert not {"signature.validation-error", "pdfsig.integrity-unknown", "signature.unparseable"} & ids(r)
    assert all(v.get("intact") is True for v in r["facts"]["signatures"]["validation"])
    assert r["verdict"]["level"] in ("info", "low")
    assert "All validated signatures are cryptographically intact." in r["summary"]["ruled_out"]


@needs_pyhanko
def test_empty_signature_field_is_not_a_doubt(analyze):
    r = analyze(pdfgen.sign(pdfgen.add_empty_signature_field(pdfgen.build(), "Empty")))
    assert "pdfsig.integrity-unknown" not in ids(r)
    assert "All validated signatures are cryptographically intact." in r["summary"]["ruled_out"]


@needs_pyhanko
def test_owner_password_only_file_is_validated(analyze):
    r = analyze(pdfgen.sign(pdfgen.owner_password_only(pdfgen.build()), encrypted=True))
    assert r["verdict"]["complete"] is True
    assert "signature.intact" in ids(r)
    assert "signature.not-validated" not in ids(r)


@needs_pyhanko
def test_other_constructor_failures_are_not_called_unparseable(analyze, monkeypatch):
    from pdfforensics.analyzers import signatures

    def fail(*a, **k):
        raise RuntimeError("unexpected reference")
    monkeypatch.setattr(signatures, "EmbeddedPdfSignature", fail)
    r = analyze(pdfgen.sign(pdfgen.build()))
    assert "signature.unparseable" not in ids(r)
    assert "signature.validation-error" in ids(r)


def test_batch_summary_lists_incomplete_files(analyze, crashing):
    from pdfforensics.summary import batch_summary
    r = analyze(pdfgen.build())
    assert batch_summary([r], [])["incomplete"] == [r["file"]["name"]]


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
