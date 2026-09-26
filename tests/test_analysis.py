import importlib
import re
import time
from datetime import datetime, timedelta, timezone

import pytest

import pdfgen
from conftest import finding, ids
from pdfforensics import raw
from pdfforensics.document import Options
from pdfforensics.engine import analyze_file


# ---------------------------------------------------------------- baseline / false-positive guards

def test_clean_document_has_no_indicators(analyze):
    r = analyze(pdfgen.build())
    assert r["verdict"]["label"] == "no-indicators", r["verdict"]
    assert r["verdict"]["complete"]
    assert r["facts"]["revisions"]["revision_count"] == 1
    assert len(r["file"]["sha256"]) == 64


def test_linearized_file_is_one_revision(analyze):
    """Upstream counted %%EOF markers, so every linearized file looked modified (defect D1)."""
    data = pdfgen.build(linearize=True)
    assert data.count(b"%%EOF") == 2
    r = analyze(data)
    assert r["facts"]["revisions"]["revision_count"] == 1
    assert r["facts"]["revisions"]["linearized"] is True
    assert not any(i.startswith("revisions.") for i in ids(r))
    assert "structure.extra-eof-markers" not in ids(r)
    assert r["verdict"]["label"] == "no-indicators"


def test_object_stream_file_parses_chain(analyze):
    r = analyze(pdfgen.build(object_streams=True))
    assert r["facts"]["structure"]["xref_style"] == "stream"
    assert r["facts"]["revisions"]["revision_count"] == 1


def test_different_creation_and_mod_dates_are_not_flagged(analyze):
    """Upstream flagged CreationDate != ModDate as modification (defect D4)."""
    c = datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc)
    r = analyze(pdfgen.build(created=c, modified=c + timedelta(minutes=3)))
    assert not any(i.startswith("metadata.") and i != "metadata.xmp-history" for i in ids(r))


def test_ocr_scan_is_not_a_shadow_attack(analyze):
    """Upstream reported OCR'd scans (invisible text + image) as shadow attacks (defect D9)."""
    r = analyze(pdfgen.build(render_mode=3, customize=pdfgen.add_scan_image))
    assert "content.ocr-text-layer" in ids(r)
    assert "content.invisible-text" not in ids(r)
    assert r["verdict"]["level"] == "info"


# ---------------------------------------------------------------- revisions

def test_incremental_content_change_is_detected_with_text_diff(analyze):
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    changed = pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK"))})
    r = analyze(changed)
    assert r["facts"]["revisions"]["revision_count"] == 2
    f = finding(r, "revisions.content-changed")
    assert f["severity"] == "high" and f["confidence"] == "high"
    assert any("100 SEK" in e["text"] for e in f["evidence"]["text_removed"])
    assert any("900 SEK" in e["text"] for e in f["evidence"]["text_added"])
    assert r["verdict"]["label"] == "significant-indicators"


def test_metadata_only_update_is_benign(analyze):
    base = pdfgen.build()
    num = pdfgen.info_objnum(base)
    upd = pdfgen.append_update(base, {num: b"<< /Producer (Acme Billing 4.2) /Creator (Acme ERP) "
                                           b"/CreationDate (D:20260301100000+01'00') /ModDate (D:20260302100000+01'00') >>"})
    r = analyze(upd)
    f = finding(r, "revisions.metadata-update")
    assert f["severity"] == "info"
    assert "revisions.content-changed" not in ids(r)


def test_raw_parser_revision_boundaries_are_standalone_files():
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    upd = pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("changed"))})
    rs = raw.parse(upd)
    assert [r.end for r in rs.revisions] == [len(base), len(upd)]
    assert rs.xref_style == "classic"


def _edit_total(data: bytes, total: str = "Total: 900 SEK") -> dict[int, bytes]:
    return {pdfgen.content_objnum(data): pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", total))}


def _assert_edit_found(r: dict) -> None:
    f = finding(r, "revisions.content-changed")
    assert any("900 SEK" in e["text"] for e in f["evidence"]["text_added"])
    assert r["verdict"]["label"] != "no-indicators"
    assert "No page content was changed through appended edits." not in r["summary"]["ruled_out"]


def test_linearized_file_with_update_has_two_revisions(analyze):
    base = pdfgen.build(linearize=True)
    r = analyze(pdfgen.append_update(base, _edit_total(base)))
    assert r["facts"]["revisions"]["revision_count"] == 2
    assert r["facts"]["revisions"]["linearized"] is True
    _assert_edit_found(r)


def test_linearized_keyword_outside_linearization_dictionary_is_ignored(analyze):
    """Only the first object of the file can be a linearization dictionary."""
    base = pdfgen.build(producer="Acme Billing 4.2 /Linearized 1 /E 999999999")
    assert b"/Linearized" in base[:2048]
    r = analyze(pdfgen.append_update(base, _edit_total(base)))
    assert r["facts"]["revisions"]["linearized"] is False
    assert r["facts"]["revisions"]["revision_count"] == 2
    _assert_edit_found(r)


def test_linearization_hint_cannot_absorb_a_later_update(analyze):
    """The first-page section is the lowest one in the file and links forward; a later update never qualifies."""
    base = pdfgen.build(linearize=True)
    e = re.search(rb"/E (\d+)", base)
    forged = base[:e.start(1)] + b"9" * len(e.group(1)) + base[e.end(1):]
    upd = pdfgen.append_update(forged, _edit_total(forged))
    assert int(b"9" * len(e.group(1))) > len(upd)
    r = analyze(upd)
    assert r["facts"]["revisions"]["revision_count"] == 2
    _assert_edit_found(r)


def test_update_without_prev_link_still_exposes_earlier_revision(analyze):
    base = pdfgen.build()
    upd = pdfgen.append_unlinked_update(base, _edit_total(base))
    r = analyze(upd)
    assert r["facts"]["revisions"]["revision_count"] == 2
    assert "structure.unlinked-revision" in ids(r)
    _assert_edit_found(r)


def test_broken_prev_link_still_exposes_earlier_revision(analyze):
    base = pdfgen.build()
    upd = pdfgen.append_update(base, _edit_total(base))
    broken = re.sub(rb"/Prev \d+", b"/Prev 7", upd)
    r = analyze(broken)
    assert "structure.xref-chain-broken" in ids(r)
    assert r["facts"]["revisions"]["revision_count"] == 2
    _assert_edit_found(r)


def test_unlinked_revision_closed_by_an_xref_stream_is_recovered():
    base = pdfgen.build(object_streams=True)
    upd = pdfgen.append_update(base, _edit_total(base))
    broken = re.sub(rb"/Prev \d+", b"/Prev 7", upd)
    rs = raw.parse(broken)
    assert [r.end for r in rs.recovered_revisions] == [len(base)]
    assert [r.end for r in rs.revisions] == [len(base), len(broken)]


def test_pdf_inside_a_stream_is_not_a_revision(analyze):
    """An uncompressed PDF carried in a stream has its own startxref/%%EOF; those are not revisions."""
    inner = pdfgen.build()
    r = analyze(pdfgen.with_orphan(pdfgen.build(), pdfgen.stream_obj(inner)))
    assert r["facts"]["revisions"]["revision_count"] == 2
    assert "structure.unlinked-revision" not in ids(r)
    assert "revisions.content-changed" not in ids(r)


def test_pdf_attached_with_indirect_length_is_not_a_revision(analyze):
    """A stream whose /Length is indirect is delimited by endstream, which an inner PDF can contain."""
    base = pdfgen.build()
    size = int(re.findall(rb"/Size\s+(\d+)", base)[-1])
    attachment = b"<< /Type /EmbeddedFile /Length %d 0 R >>\nstream\n" % (size + 1) + base + b"\nendstream"
    r = analyze(pdfgen.append_update(base, {size: attachment, size + 1: b"%d" % len(base)}))
    assert "structure.unlinked-revision" not in ids(r)
    assert r["facts"]["revisions"]["revision_count"] == 2


def test_direct_length_pattern_ignores_indirect_references():
    assert raw._DIRECT_LENGTH_RE.search(b"<< /Length 12 0 R >>") is None
    assert raw._DIRECT_LENGTH_RE.search(b"<< /Length 12 >>").group(1) == b"12"


@pytest.mark.parametrize("junk", [b">>\nstream\nendstream\n", b"startxref %d %%%%EOF "],
                         ids=["stream-headers", "startxref-markers"])
def test_raw_parser_stays_linear_on_repeated_markers(junk):
    base = pdfgen.build()
    size = int(re.findall(rb"/Size\s+(\d+)", base)[-1])
    probe = pdfgen.append_update(base, {size: b"<< /A 1 >>", size + 1: b"()"})
    if b"%d" in junk:
        junk = junk % probe.find(b"%d 0 obj" % size, len(base))
    data = pdfgen.append_update(base, {size: b"<< /A 1 >>", size + 1: b"(" + junk * 40000 + b")"})
    start = time.perf_counter()
    raw.parse(data)
    assert time.perf_counter() - start < 2.0


def test_content_change_before_skipped_revisions_is_still_found(tmp_path):
    base = pdfgen.build()
    data = pdfgen.append_update(base, _edit_total(base))
    info = pdfgen.info_objnum(base)
    for i in range(6):
        data = pdfgen.append_update(data, {info: b"<< /Producer (Acme Billing 4.2) /Title (t%d) >>" % i})
    p = tmp_path / "doc.pdf"
    p.write_bytes(data)
    r = analyze_file(p, Options(max_revisions=3, external_tools=False)).to_dict()
    assert r["facts"]["revisions"]["revisions_skipped"] > 0
    assert "revisions.not-all-compared" in ids(r)
    _assert_edit_found(r)


# ---------------------------------------------------------------- signatures

def _have_pyhanko() -> bool:
    # find_spec("pyhanko") is not enough: after an uninstall a namespace remnant can remain
    try:
        importlib.import_module("pyhanko.sign")
        return True
    except ImportError:
        return False


needs_pyhanko = pytest.mark.skipif(not _have_pyhanko(), reason="pyHanko not installed")


@needs_pyhanko
def test_signed_document_is_not_reported_as_tampered(analyze):
    """Every signature is an incremental update; upstream scored that as tampering (defect D14)."""
    r = analyze(pdfgen.sign(pdfgen.build()))
    assert r["facts"]["signatures"]["signature_count"] == 1
    assert "signature.intact" in ids(r)
    assert "revisions.signature-update" in ids(r)
    assert r["verdict"]["level"] in ("info", "low"), r["verdict"]


@needs_pyhanko
def test_signature_validation_uses_explicit_empty_trust_roots(analyze, recwarn):
    """pyHanko deprecated the implicit fall-back to the OS TLS trust list; trust is not evaluated here."""
    r = analyze(pdfgen.sign(pdfgen.build()))
    assert not [w for w in recwarn if "trust list" in str(w.message)]
    assert finding(r, "signature.intact")["evidence"]["trusted"] is False


@needs_pyhanko
def test_content_change_after_signing_is_critical(analyze):
    signed = pdfgen.sign(pdfgen.build())
    num = pdfgen.content_objnum(signed)
    tampered = pdfgen.append_update(signed, {num: pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 9 SEK"))})
    r = analyze(tampered)
    f = finding(r, "revisions.content-changed")
    assert f["severity"] == "critical"
    assert "signature.bytes-after-last-signature" in ids(r)
    assert r["verdict"]["label"] == "strong-indicators"


# ---------------------------------------------------------------- metadata

def test_modified_before_created(analyze):
    c = datetime(2026, 5, 10, 12, 0, tzinfo=timezone.utc)
    r = analyze(pdfgen.build(created=c, modified=c - timedelta(days=40)))
    f = finding(r, "metadata.modified-before-created")
    assert f["confidence"] == "high"


def test_info_xmp_mismatch(analyze):
    c = datetime(2026, 5, 10, 12, 0, tzinfo=timezone.utc)
    r = analyze(pdfgen.build(created=c, xmp_create=c - timedelta(days=3)))
    assert "metadata.info-xmp-date-mismatch" in ids(r)


def test_info_xmp_same_instant_different_timezone_is_fine(analyze):
    """Upstream compared the first 10 characters and ignored timezones (defect D6)."""
    c = datetime(2026, 5, 10, 23, 30, tzinfo=timezone(timedelta(hours=2)))
    r = analyze(pdfgen.build(created=c, xmp_create=c.astimezone(timezone.utc)))
    assert "metadata.info-xmp-date-mismatch" not in ids(r)


def test_online_editor_producer(analyze):
    r = analyze(pdfgen.build(producer="iLovePDF"))
    assert finding(r, "metadata.editor-tool")["severity"] == "medium"


def test_browser_print_is_not_suspicious(analyze):
    """Upstream gave Chrome-printed PDFs +15 risk via a duplicated list (defect D8)."""
    r = analyze(pdfgen.build(producer="Skia/PDF m120", creator="Mozilla/5.0 Chrome/120"))
    assert "metadata.editor-tool" not in ids(r)
    assert r["facts"]["fingerprint"]["producer_family"] == "Chrome/Skia"


# ---------------------------------------------------------------- content & active content

def test_invisible_text_in_form_xobject(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_invisible_text_in_xobject))
    f = finding(r, "content.invisible-text")
    assert f["evidence"]["pages"][0]["invisible_chars"] > 0


def test_print_only_annotation(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_print_only_annotation))
    assert "content.print-only-annotations" in ids(r)


def test_layer_hidden_by_default(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_hidden_layer))
    assert "content.layers-hidden-by-default" in ids(r)


def test_javascript_open_action(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_open_action_js))
    assert finding(r, "active.javascript")["severity"] == "high"


def test_embedded_file(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_embedded_file))
    assert "notes.txt" in finding(r, "active.embedded-files")["evidence"]["files"]


def test_direct_javascript_action_inside_annotation(analyze):
    r = analyze(pdfgen.build(customize=pdfgen.add_link_with_direct_js_action))
    f = finding(r, "active.javascript")
    assert any("inside" in o for o in f["evidence"]["objects"])


def test_direct_filespec_in_name_tree(analyze):
    """Found during validation on py-pdf/sample-files 025-attachment."""
    r = analyze(pdfgen.build(customize=pdfgen.add_direct_filespec_attachment))
    assert "image.png" in finding(r, "active.embedded-files")["evidence"]["files"]


# ---------------------------------------------------------------- structure

def test_orphan_text_stream_is_low(analyze):
    r = analyze(pdfgen.with_orphan(pdfgen.build(), pdfgen.ORPHAN_TEXT))
    f = finding(r, "structure.unreachable-objects")
    assert f["severity"] == "low" and f["evidence"]["content_bearing"]


def test_orphan_font_is_info_only(analyze):
    """Unused fonts/resources are common (8 of 21 public samples); they must not raise the verdict."""
    r = analyze(pdfgen.with_orphan(pdfgen.build(), pdfgen.ORPHAN_FONT))
    assert finding(r, "structure.unreachable-objects")["severity"] == "info"
    assert r["verdict"]["label"] == "no-indicators"


def test_trailing_data_after_eof(analyze):
    r = analyze(pdfgen.build() + b"\nSECRET-APPENDED-PAYLOAD")
    assert finding(r, "structure.data-after-eof")["evidence"]["bytes"] > 0


def test_data_before_header(analyze):
    r = analyze(b"JUNK" + pdfgen.build())
    assert "structure.data-before-header" in ids(r)
