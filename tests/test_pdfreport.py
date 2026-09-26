import io

import pikepdf
import pytest

import pdfgen
from pdfforensics import analyzers, pdfreport
from pdfforensics.cli import main

pytestmark = pytest.mark.skipif(not pdfreport.available(), reason="reportlab not installed")


def _text(path) -> str:
    from pypdf import PdfReader
    return "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)


def _edited() -> bytes:
    base = pdfgen.build()
    return pdfgen.append_update(base, {
        pdfgen.content_objnum(base): pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK")),
        pdfgen.info_objnum(base): b"<< /Producer (Acme PDF Editor 3) /ModDate (D:20260310121500+01'00') >>"})


def test_pdf_report_contains_verdict_hash_and_changes(analyze, tmp_path):
    r = analyze(_edited())
    out = tmp_path / "report.pdf"
    pdfreport.write_pdf_report(r, out)
    with pikepdf.open(out):
        pass
    text = _text(out)
    assert r["verdict"]["label"] in text
    assert r["file"]["sha256"][:16] in text.replace("\n", "")
    assert "Total: 100 SEK" in text and "Total: 900 SEK" in text
    assert "claimed" in text


def test_pdf_report_survives_hostile_text(analyze, tmp_path):
    base = pdfgen.build()
    nasty = pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.stream_obj(
        pdfgen.text_stream("<b>bold</b> & <font size=90>big</font>"))})
    r = analyze(nasty)
    # the fixture's content stream is Latin-1, so put text outside Windows-1252 straight into the report
    event = r["facts"]["timeline"]["events"][-1]
    event["after"] = event["after"] + ["\u03a9\u2248 \u6f22\u5b57 \u202e \U0001f600"]
    event["who"] = "Editor \u6f22\u5b57 <script>"
    out = tmp_path / "nasty.pdf"
    pdfreport.write_pdf_report(r, out)
    text = _text(out)
    assert "<b>bold</b>" in text
    assert "<script>" in text
    assert "\u2248" in text  # kept, not replaced by "?" (not in Windows-1252)


def test_pdf_report_says_when_timeline_is_missing(analyze, tmp_path):
    r = analyze(pdfgen.build())
    r["facts"].pop("timeline")
    r["errors"].append({"analyzer": "timeline", "error": "RuntimeError: simulated"})
    r["verdict"]["complete"] = False
    out = tmp_path / "missing.pdf"
    pdfreport.write_pdf_report(r, out)
    text = _text(out)
    assert "Timeline unavailable" in text
    assert "incomplete" in text.lower()


def test_pdf_report_cli_single_file(tmp_path, capsys):
    src = tmp_path / "doc.pdf"
    src.write_bytes(_edited())
    out = tmp_path / "out" / "doc-report.pdf"
    assert main(["analyze", str(src), "--no-prompt", "--no-external-tools", "--pdf-report", str(out)]) == 0
    assert out.exists() and out.read_bytes().startswith(b"%PDF-")


def test_pdf_report_per_file_in_batch(tmp_path, capsys):
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "doc.pdf").write_bytes(pdfgen.build(producer=f"Acme {sub}"))
    out = tmp_path / "reports"
    assert main(["analyze", str(tmp_path / "a" / "doc.pdf"), str(tmp_path / "b" / "doc.pdf"),
                 "--no-prompt", "--no-external-tools", "--pdf-report", str(out)]) == 0
    assert len(list(out.glob("*.forensics-report.pdf"))) == 2


def test_pdf_report_handles_a_page_that_was_fully_rewritten(analyze, tmp_path):
    lines = [f"Row {i:03d} amount {i * 100},00 balance {i * 1000},52 reference INV-{i:05d} and more text"
             for i in range(120)]
    base = pdfgen.build(lines)
    edited = pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.stream_obj(
        pdfgen.text_stream(*[x.replace("amount", "AMOUNT") for x in lines]))})
    out = tmp_path / "long.pdf"
    pdfreport.write_pdf_report(analyze(edited), out)
    assert "Row 119" in _text(out)


def test_pdf_report_does_not_call_a_self_issued_timestamp_trusted(analyze, tmp_path):
    pytest.importorskip("pyhanko.sign")
    out = tmp_path / "ts.pdf"
    pdfreport.write_pdf_report(analyze(pdfgen.document_timestamp(pdfgen.build())), out)
    text = _text(out).replace("\n", " ")
    assert "trusted timestamp" not in text
    assert "issuer not verified" in text


def test_pdf_report_not_available_for_spreadsheets(analyze, tmp_path):
    import officegen
    out = tmp_path / "x.pdf"
    pdfreport.write_pdf_report(analyze(officegen.build("xlsx"), name="book.xlsx"), out)
    assert "not available for this format" in _text(out)


def test_pdf_report_dir_when_one_of_several_inputs_fails(tmp_path, capsys):
    good = tmp_path / "good.pdf"
    good.write_bytes(pdfgen.build())
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(b"%PDF-1.4\nnot a pdf")
    out = tmp_path / "reports"
    main(["analyze", str(good), str(bad), "--no-prompt", "--no-external-tools", "--pdf-report", str(out)])
    assert out.is_dir() and len(list(out.glob("*.forensics-report.pdf"))) == 1


def test_pdf_report_worst_case_row_fits_a_page(analyze, tmp_path):
    """Every line at the 200-character excerpt limit: rows must still fit without splitting."""
    lines = [f"{i:03d} " + ("W" * 300) for i in range(40)]
    base = pdfgen.build(lines)
    edited = pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.stream_obj(
        pdfgen.text_stream(*[x.replace("W", "M") for x in lines]))})
    out = tmp_path / "wide.pdf"
    pdfreport.write_pdf_report(analyze(edited), out)
    assert "039" in _text(out)
