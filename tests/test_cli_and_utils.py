import json
from datetime import timedelta

import pikepdf
import pytest

import pdfgen
from pdfforensics import document
from pdfforensics.cli import main
from pdfforensics.pdfutil import parse_pdf_date, parse_xmp_date


def test_parse_pdf_date_with_offset_and_partial():
    d = parse_pdf_date("D:20260301103000+01'00'")
    assert d.utcoffset() == timedelta(hours=1) and d.hour == 10
    assert parse_pdf_date("D:2026").year == 2026
    assert parse_pdf_date("D:20260301").tzinfo is None
    assert parse_pdf_date("D:20260301120000Z").utcoffset() == timedelta(0)
    assert parse_pdf_date("garbage") is None


def test_parse_xmp_date():
    assert parse_xmp_date("2026-03-01T10:00:00Z").utcoffset() == timedelta(0)
    assert parse_xmp_date("2026-03").month == 3


def test_not_a_pdf_is_rejected(tmp_path):
    p = tmp_path / "x.pdf"
    p.write_bytes(b"hello world")
    with pytest.raises(document.InputError):
        document.load(p)
    assert main(["analyze", str(p)]) == 2


def test_cli_json_and_fail_on(tmp_path, capsys):
    p = tmp_path / "js.pdf"
    p.write_bytes(pdfgen.build(customize=pdfgen.add_open_action_js))
    out = tmp_path / "r.json"
    rc = main(["analyze", str(p), "--json", str(out), "--fail-on", "high"])
    assert rc == 1
    data = json.loads(out.read_text())
    assert data["file"]["sha256"] and data["tool"]["pikepdf"] == pikepdf.__version__
    assert data["verdict"]["level"] == "high"


def test_cli_batch_out_dir(tmp_path, capsys):
    src = tmp_path / "in"
    src.mkdir()
    (src / "a.pdf").write_bytes(pdfgen.build())
    (src / "b.pdf").write_bytes(pdfgen.build(producer="iLovePDF"))
    (src / "c.pdf").write_bytes(b"not a pdf")
    out = tmp_path / "out"
    assert main(["analyze", str(src), "--out-dir", str(out)]) == 0
    assert len(list(out.glob("a.pdf.*.forensics.json"))) == 1
    assert len(list(out.glob("b.pdf.*.forensics.md"))) == 1
    summary = (out / "batch-summary.md").read_text()
    assert "not-analysed" in summary and "a.pdf" in summary


def test_extract_revisions(tmp_path, capsys):
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    upd = pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("Total: 900 SEK"))})
    p = tmp_path / "inv.pdf"
    p.write_bytes(upd)
    out = tmp_path / "revs"
    assert main(["extract-revisions", str(p), "--out-dir", str(out)]) == 0
    files = sorted(out.iterdir())
    assert len(files) == 2
    assert files[0].read_bytes() == base
    with pikepdf.open(files[0]) as pdf:
        assert b"100 SEK" in pdf.pages[0].obj.Contents.read_bytes()


def test_compare(tmp_path, capsys):
    a, b = tmp_path / "a.pdf", tmp_path / "b.pdf"
    a.write_bytes(pdfgen.build())
    b.write_bytes(pdfgen.build(lines=("Invoice 2026-001", "Total: 900 SEK"), producer="iLovePDF"))
    assert main(["compare", str(a), str(b)]) == 0
    text = capsys.readouterr().out
    assert "900 SEK" in text and "Producer" in text


def test_markdown_report_renders(tmp_path, capsys):
    p = tmp_path / "doc.pdf"
    p.write_bytes(pdfgen.build(customize=pdfgen.add_hidden_layer))
    assert main(["analyze", str(p)]) == 0
    md = capsys.readouterr().out
    assert "# PDF forensic report" in md and "SHA-256" in md and "Layers hidden by default" in md
