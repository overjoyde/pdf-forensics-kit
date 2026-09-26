"""Stream decoding is bounded: small hostile files must not decode to gigabytes."""

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
    assert not pdfutil.stream_fits(st, 1 << 20)


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


def test_non_flate_chain_whose_worst_case_is_too_large_is_refused():
    rle = (bytes([129]) + b" ") * 20000 + b"\x80"      # each pair expands to 128 bytes
    st = _stream(rle, ["/RunLengthDecode"])
    assert not pdfutil.stream_fits(st, 1 << 20)
    with pytest.raises(pdfutil.StreamTooLarge):
        pdfutil.read_stream(st, 1 << 20)


def test_xmp_bomb_is_reported_not_decoded(analyze):
    data = pdfgen.with_metadata_stream(pdfgen.build(), pdfgen.flate_bomb_obj(64, b"/Type /Metadata /Subtype /XML"))
    r = analyze(data)
    f = finding(r, "analysis.stream-too-large")
    assert f["category"] == "metadata"
    assert "Metadata dates and producer information are consistent." not in r["summary"]["ruled_out"]


def test_unreferenced_stream_bomb_is_reported(analyze):
    r = analyze(pdfgen.with_orphan(pdfgen.build(), pdfgen.flate_bomb_obj(96)))
    assert any(f["id"] == "analysis.stream-too-large" and f["category"] == "structure" for f in r["findings"])


def test_page_content_bomb_is_reported_not_parsed(analyze):
    base = pdfgen.build()
    r = analyze(pdfgen.append_update(base, {pdfgen.content_objnum(base): pdfgen.flate_bomb_obj(96)}))
    assert any(f["id"] == "analysis.stream-too-large" and f["category"] == "content" for f in r["findings"])
    assert "No hidden text, print-only annotations or hidden layers." not in r["summary"]["ruled_out"]
    assert "analysis.error" not in ids(r)
