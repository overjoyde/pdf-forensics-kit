"""Edit timeline: what changed, when, and to what."""

import importlib

import pytest

import officegen
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


def _edited_with_moddate(moddate: str) -> bytes:
    base = pdfgen.build()
    info = pdfgen.info_objnum(base)
    return pdfgen.append_update(base, {
        pdfgen.content_objnum(base): pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK")),
        info: b"<< /Producer (Acme PDF Editor 3) /ModDate (" + moddate.encode() + b") >>",
    })


def test_each_revision_records_its_claimed_save_time(analyze):
    r = analyze(_edited_with_moddate("D:20260310121500+01'00'"))
    times = {t["revision"]: t for t in r["facts"]["revisions"]["revision_times"]}
    assert times[2]["info_mod"] == "2026-03-10T12:15:00+01:00"
    assert times[2]["producer"] == "Acme PDF Editor 3"
    assert times[1]["info_mod"] != times[2]["info_mod"]


TRACKED = ('<w:p><w:r><w:t>Invoice total: </w:t></w:r>'
           '<w:del w:id="1" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
           '<w:r><w:delText>100 SEK</w:delText></w:r></w:del>'
           '<w:ins w:id="2" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
           '<w:r><w:t>900 SEK</w:t></w:r></w:ins></w:p>')


def test_word_tracked_changes_are_kept_individually(analyze):
    r = analyze(officegen.build("docx", main=officegen.word_body(TRACKED)), name="doc.docx")
    changes = r["facts"]["office_content"]["tracked_changes"]
    assert [(c["type"], c["author"], c["date"], c["text"]) for c in changes] == [
        ("del", "Anna Andersson", "2026-03-02T09:15:00Z", "100 SEK"),
        ("ins", "Anna Andersson", "2026-03-02T09:15:00Z", "900 SEK"),
    ]
