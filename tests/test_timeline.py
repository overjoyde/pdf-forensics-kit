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


def _events(r, kind=None):
    return [e for e in r["facts"]["timeline"]["events"] if kind is None or e["kind"] == kind]


def test_content_change_has_time_before_and_after(analyze):
    r = analyze(_edited_with_moddate("D:20260310121500+01'00'"))
    [e] = _events(r, "content-change")
    assert e["revision"] == 2
    assert e["when"] == "2026-03-10T12:15:00+01:00"
    assert e["time_evidence"] == "claimed" and "ModDate" in e["time_source"]
    assert e["paired"] and e["before"] == ["Total: 100 SEK"] and e["after"] == ["Total: 900 SEK"]
    assert e["who"] == "Acme PDF Editor 3"


def test_events_are_in_time_order(analyze):
    times = [e["when"] for e in _events(analyze(_edited_with_moddate("D:20260310121500+01'00'"))) if e["when"]]
    assert times == sorted(times)


def test_later_revision_claiming_an_earlier_time_is_flagged(analyze):
    r = analyze(_edited_with_moddate("D:20200101000000Z"))
    assert finding(r, "timeline.inconsistent-times")["severity"] == "medium"


def test_naive_and_aware_times_do_not_crash(analyze):
    r = analyze(_edited_with_moddate("D:20260310121500"))
    assert "timeline" in r["facts"]
    assert not [e for e in r["errors"] if e["analyzer"] == "timeline"]


def test_unreadable_revision_is_listed(analyze):
    base = pdfgen.build()
    broken = pdfgen.append_update(base, {pdfgen.content_objnum(base): b"<< /Length 5 >>\nstream\nxx"})
    events = _events(analyze(broken))
    assert any(e["kind"] in ("unreadable-revision", "revision", "content-change") and e["revision"] == 2
               for e in events)


@needs_pyhanko
def test_signed_then_edited_marks_change_after_signing(analyze):
    signed = pdfgen.sign(pdfgen.build())
    edited = pdfgen.append_update(signed, {pdfgen.content_objnum(signed): pdfgen.stream_obj(
        pdfgen.text_stream("Invoice 2026-001", "Total: 9 SEK"))})
    r = analyze(edited)
    [sig] = _events(r, "signature")
    assert sig["time_evidence"] == "signed"
    assert all(e["after_signing"] for e in _events(r, "content-change"))


@needs_pyhanko
def test_document_timestamp_is_timestamped(analyze):
    [ts] = _events(analyze(pdfgen.document_timestamp(pdfgen.build())), "timestamp")
    assert ts["time_evidence"] == "timestamped" and ts["when"]


def test_word_delete_then_insert_is_one_change(analyze):
    r = analyze(officegen.build("docx", main=officegen.word_body(TRACKED)), name="doc.docx")
    [e] = _events(r, "tracked-change")
    assert (e["before"], e["after"], e["who"]) == (["100 SEK"], ["900 SEK"], "Anna Andersson")
    assert e["when"] == "2026-03-02T09:15:00+00:00" and e["time_evidence"] == "claimed"


def test_revision_that_could_not_be_opened_stays_in_the_timeline():
    from pdfforensics import timeline
    facts = {"revisions": {"revision_times": [{"revision": 1, "end": 900, "info_mod": None, "info_created": None,
                                               "xmp_modify": None, "producer": ""}],
                           "updates": [{"revision": 2, "end": 1200, "error": "cannot open: damaged"}]}}
    events = timeline.build(facts, "pdf").facts["events"]
    assert [(e["kind"], e["revision"]) for e in events if e["kind"] == "unreadable-revision"] == [
        ("unreadable-revision", 2)]


def test_pdf_report_without_reportlab_exits_2(tmp_path, monkeypatch, capsys):
    from pdfforensics import pdfreport
    from pdfforensics.cli import main
    monkeypatch.setattr(pdfreport, "available", lambda: False)
    src = tmp_path / "doc.pdf"
    src.write_bytes(pdfgen.build())
    out = tmp_path / "r.pdf"
    assert main(["analyze", str(src), "--no-prompt", "--no-external-tools", "--pdf-report", str(out)]) == 2
    assert not out.exists()
    assert "pdf-forensics-kit[report]" in capsys.readouterr().err


@needs_pyhanko
def test_backdated_edit_after_signing_stays_after_the_signature(analyze):
    """Revision order is proven by the bytes; a claimed time is not. A backdated edit keeps its place."""
    signed = pdfgen.sign(pdfgen.build())
    edited = pdfgen.append_update(signed, {
        pdfgen.content_objnum(signed): pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 9 SEK")),
        pdfgen.info_objnum(signed): b"<< /Producer (Acme PDF Editor 3) /ModDate (D:20200101000000Z) >>"})
    r = analyze(edited)
    kinds = [e["kind"] for e in _events(r) if e["kind"] in ("signature", "content-change")]
    assert kinds == ["signature", "content-change"]
    assert "timeline.inconsistent-times" in ids(r)


# ---------------------------------------------------------------- final review findings

def test_revision_that_did_not_write_a_save_time_claims_none(analyze):
    """An update that leaves /Info alone inherits the earlier /ModDate; that is not its own save time."""
    base = pdfgen.build()
    upd = pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.stream_obj(
        pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK"))})
    [e] = _events(analyze(upd), "content-change")
    assert e["when"] is None
    assert "no save time" in e["what"].lower() or "no save time" in e["time_source"].lower()


@needs_pyhanko
def test_time_in_a_broken_signature_is_only_claimed(analyze):
    signed = pdfgen.sign(pdfgen.build())
    i = signed.find(b"Total: 100 SEK")
    broken = signed[:i] + b"Total: 999 SEK" + signed[i + 14:]
    [sig] = _events(analyze(broken), "signature")
    assert sig["time_evidence"] == "claimed"


@needs_pyhanko
def test_signing_time_without_the_signed_attribute_is_only_claimed(analyze, monkeypatch):
    from pdfforensics.analyzers import signatures
    monkeypatch.setattr(signatures, "extract_self_reported_ts", lambda signer_info: None)
    r = analyze(pdfgen.sign(pdfgen.build()))
    assert "signer_reported_time" not in r["facts"]["signatures"]["validation"][0]
    [sig] = _events(r, "signature")
    assert sig["time_evidence"] == "claimed" and "/M" in sig["time_source"]


SPLIT_RUNS = ('<w:p>'
              '<w:del w:id="1" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
              '<w:r><w:delText>Total </w:delText></w:r></w:del>'
              '<w:del w:id="2" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
              '<w:r><w:rPr><w:b/></w:rPr><w:delText>100 SEK</w:delText></w:r></w:del>'
              '<w:ins w:id="3" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
              '<w:r><w:t>Sum </w:t></w:r></w:ins>'
              '<w:ins w:id="4" w:author="Anna Andersson" w:date="2026-03-02T09:15:00Z">'
              '<w:r><w:rPr><w:b/></w:rPr><w:t>900 SEK</w:t></w:r></w:ins></w:p>')


def test_word_change_split_over_runs_is_one_change(analyze):
    r = analyze(officegen.build("docx", main=officegen.word_body(SPLIT_RUNS)), name="doc.docx")
    [e] = _events(r, "tracked-change")
    assert (e["before"], e["after"]) == (["Total 100 SEK"], ["Sum 900 SEK"])


def test_spreadsheet_timeline_is_marked_not_covered(analyze):
    r = analyze(officegen.build("xlsx"), name="book.xlsx")
    assert r["facts"]["timeline"]["covered"] is False


def test_backdated_revision_with_a_naive_date_is_flagged(analyze):
    r = analyze(_edited_with_moddate("D:20200101000000"))
    assert "timeline.inconsistent-times" in ids(r)
