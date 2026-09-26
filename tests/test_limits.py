"""Stream decoding is bounded: small hostile files must not decode to gigabytes."""

import io
import re
import zlib

import pikepdf
import pytest

import pdfgen
from conftest import finding, ids
from pdfforensics import pdfutil


_OWNERS: list[pikepdf.Pdf] = []  # a stream is only valid while its Pdf is alive


def _stream(data: bytes, filters: list[str]) -> pikepdf.Stream:
    pdf = pikepdf.new()
    _OWNERS.append(pdf)
    st = pikepdf.Stream(pdf, b"")
    names = [pikepdf.Name(f) for f in filters]
    st.write(data, filter=(names[0] if len(names) == 1 else pikepdf.Array(names)) if names else None)
    return st


@pytest.fixture
def no_full_decode(monkeypatch):
    def refuse(self, *a, **k):
        raise AssertionError("read_bytes() decodes the whole stream")
    monkeypatch.setattr(pikepdf.Object, "read_bytes", refuse)


def test_flate_stream_is_read_up_to_the_limit_only(no_full_decode):
    st = _stream(zlib.compress(b" " * (64 << 20), 9), ["/FlateDecode"])
    data, truncated = pdfutil.read_stream(st, 1 << 20)
    assert truncated and len(data) == 1 << 20
    assert pdfutil.decoded_size(st, 1 << 20) is None


def test_nested_flate_is_bounded(no_full_decode):
    inner = zlib.compress(b"x" * (32 << 20), 9)
    st = _stream(zlib.compress(inner, 9), ["/FlateDecode", "/FlateDecode"])
    data, truncated = pdfutil.read_stream(st, 4096)
    assert truncated and data == b"x" * 4096


def test_small_streams_decode_exactly():
    text = b"BT /F1 12 Tf (Total: 100 SEK) Tj ET"
    assert pdfutil.read_stream(_stream(zlib.compress(text), ["/FlateDecode"]), 1 << 20) == (text, False)
    assert pdfutil.read_stream(_stream(text, []), 1 << 20) == (text, False)
    hexed = zlib.compress(text).hex().encode() + b">"
    assert pdfutil.read_stream(_stream(hexed, ["/ASCIIHexDecode", "/FlateDecode"]), 1 << 20) == (text, False)


def test_non_flate_chain_whose_worst_case_is_too_large_is_refused(no_full_decode):
    rle = (bytes([129]) + b" ") * (1 << 21) + b"\x80"   # each pair may expand to 128 bytes: 512 MiB
    st = _stream(rle, ["/RunLengthDecode"])
    assert pdfutil.decoded_size(st, 1 << 20) is None
    with pytest.raises(pdfutil.StreamTooLarge):
        pdfutil.read_stream(st, 1 << 20)


def test_legacy_lzw_stream_decodes_like_qpdf():
    text = b" ".join(b"BT /F1 12 Tf 72 %d Td (Line %d) Tj ET" % (700 - i, i) for i in range(4000))
    st = _stream(pdfgen.lzw_encode(text), ["/LZWDecode"])
    assert len(st.read_raw_bytes()) > 20000
    assert pdfutil.read_stream(st, 1 << 20) == (text, False)
    assert pdfutil.decoded_size(st, 64 << 20) == len(text)


@pytest.mark.parametrize("damage", ["checksum", "middle"])
def test_corrupt_flate_keeps_what_qpdf_keeps(damage):
    text = bytes(range(256)) * 3000
    comp = zlib.compress(text, 6)
    if damage == "checksum":
        comp = comp[:-4] + b"\0\0\0\0"
    else:
        mid = len(comp) // 2
        comp = comp[:mid] + b"\xff" * 40 + comp[mid + 40:]
    st = _stream(comp, ["/FlateDecode"])
    assert pdfutil.read_stream(st, 1 << 30)[0] == st.read_bytes()


def test_unreadable_flate_header_raises_like_qpdf():
    st = _stream(b"\x00\x00" + zlib.compress(b"x" * 100)[2:], ["/FlateDecode"])
    with pytest.raises(Exception):
        st.read_bytes()
    with pytest.raises(ValueError):
        pdfutil.read_stream(st, 1 << 20)


def test_xmp_bomb_is_reported_not_decoded(analyze):
    data = pdfgen.with_metadata_stream(pdfgen.build(), pdfgen.flate_bomb_obj(64, b"/Type /Metadata /Subtype /XML"))
    r = analyze(data)
    assert finding(r, "metadata.xmp-too-large")["category"] == "metadata"
    assert "Metadata dates and producer information are consistent." not in r["summary"]["ruled_out"]


def test_unreferenced_stream_bomb_is_reported(analyze):
    r = analyze(pdfgen.with_orphan(pdfgen.build(), pdfgen.flate_bomb_obj(96)))
    assert "structure.stream-too-large" in ids(r)


def test_page_content_bomb_is_reported_not_parsed(analyze):
    base = pdfgen.build()
    r = analyze(pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.flate_bomb_obj(96)}))
    assert "content.stream-too-large" in ids(r)
    assert "No hidden text, print-only annotations or hidden layers." not in r["summary"]["ruled_out"]
    assert "analysis.error" not in ids(r)


def test_unreferenced_hex_and_flate_content_is_still_recognised(analyze):
    body = b"BT /F1 12 Tf 72 700 Td (Total: 100 SEK) Tj ET\n" * 200
    hexed = zlib.compress(body).hex().encode() + b">"
    obj = b"<< /Length %d /Filter [/ASCIIHexDecode /FlateDecode] >>\nstream\n" % len(hexed) + hexed + b"\nendstream"
    r = analyze(pdfgen.with_orphan(pdfgen.build(), obj))
    assert finding(r, "structure.unreachable-objects")["severity"] == "low"
    assert "structure.stream-too-large" not in ids(r)


def test_legacy_lzw_page_content_is_scanned(analyze):
    base = pdfgen.build()
    text = b" ".join(b"BT /F1 12 Tf 72 %d Td (Line %d) Tj ET" % (700 - i % 600, i) for i in range(4000))
    comp = pdfgen.lzw_encode(text)
    obj = b"<< /Length %d /Filter /LZWDecode >>\nstream\n" % len(comp) + comp + b"\nendstream"
    r = analyze(pdfgen.append_update(base, {pdfgen.content_objnum(base): obj}))
    assert "content.stream-too-large" not in ids(r)
    assert r["facts"]["content"]["pages"][0]["text_chars"] > 20000


def test_repeated_content_streams_share_one_page_budget(analyze, monkeypatch):
    from pdfforensics.analyzers import content
    monkeypatch.setattr(content, "MAX_PAGE_CONTENT_BYTES", 1 << 20)
    base = pdfgen.build()
    size = int(re.findall(rb"/Size\s+(\d+)", base)[-1])
    with pikepdf.open(io.BytesIO(base)) as pdf:
        page_num = pdf.pages[0].obj.objgen[0]
        page_body = pdf.pages[0].obj.unparse(resolved=True)
    chunk = pdfgen.stream_obj(b"0 g\n" * (600 << 8))            # 600 KiB each, under the limit alone
    page = re.sub(rb"/Contents \d+ 0 R", b"/Contents [%d 0 R %d 0 R]" % (size, size), page_body)
    r = analyze(pdfgen.append_update(base, {size: chunk, page_num: page}))
    assert "content.stream-too-large" in ids(r)


def test_content_is_parsed_without_building_an_instruction_list(analyze, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("parse_content_stream builds every instruction in memory")
    monkeypatch.setattr(pikepdf, "parse_content_stream", refuse)
    r = analyze(pdfgen.build())
    assert r["facts"]["content"]["pages"][0]["text_chars"] > 0
    assert "content.stream-too-large" not in ids(r)


def test_damaged_operator_does_not_stop_the_page_scan(analyze):
    base = pdfgen.build()
    body = b"q \xe5\xff Q BT /F1 12 Tf 72 700 Td (Total: 100 SEK) Tj ET"
    r = analyze(pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.stream_obj(body)}))
    page = r["facts"]["content"]["pages"][0]
    assert page["text_chars"] == len("Total: 100 SEK")
    assert not r["facts"]["content"].get("page_errors")
