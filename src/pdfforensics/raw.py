"""Byte-level structure parsing: header, revisions (startxref -> /Prev chain), trailing data.

Upstream counted ``%%EOF`` markers to find incremental updates. That misreads linearized files
(which always have two), and it matches ``%%EOF`` inside streams. Here, revisions come from
the cross-reference chain itself. Each section is found through ``startxref`` and then
``/Prev``, for classic tables and cross-reference streams alike. The linearization
first-page section is merged into the revision it belongs to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_WS = b" \t\r\n\f\x00"
_STARTXREF_RE = re.compile(rb"startxref\s+(\d+)\s+%%EOF")
_OBJ_HEADER_RE = re.compile(rb"\s*(\d+)\s+(\d+)\s+obj")
_PREV_RE = re.compile(rb"/Prev\s+(\d+)")
_XREFSTM_RE = re.compile(rb"/XRefStm\s+(\d+)")
_EOF_RE = re.compile(rb"%%EOF")
_LINEARIZED_RE = re.compile(rb"/Linearized\s")
_LIN_E_RE = re.compile(rb"/E\s+(\d+)")
_SUBSECTION_RE = re.compile(rb"(\d+)\s+(\d+)\s*[\r\n]")

MAX_SECTIONS = 2000


@dataclass
class XrefSection:
    offset: int              # byte offset of the xref keyword / xref stream object
    kind: str                # "classic" | "stream" | "unknown"
    prev: int | None         # /Prev offset
    xrefstm: int | None      # /XRefStm (hybrid-reference files)
    end: int                 # end of the %%EOF line that closes this section
    entry_count: int = 0     # classic tables only
    linearization_first_page: bool = False


@dataclass
class Revision:
    index: int               # 1-based, oldest first
    end: int                 # byte offset: data[:end] is this revision as a standalone file
    sections: list[XrefSection] = field(default_factory=list)


@dataclass
class RawStructure:
    size: int
    header_offset: int
    header_version: str | None
    linearized: bool
    sections: list[XrefSection]          # newest first, as walked
    revisions: list[Revision]            # oldest first
    eof_marker_count: int
    trailing_bytes: int                  # non-whitespace bytes after the final %%EOF
    trailing_preview: str
    chain_errors: list[str]

    @property
    def xref_style(self) -> str:
        kinds = {s.kind for s in self.sections}
        hybrid = any(s.xrefstm is not None for s in self.sections)
        if hybrid:
            return "hybrid"
        if kinds == {"classic"}:
            return "classic"
        if kinds == {"stream"}:
            return "stream"
        if not kinds:
            return "unknown"
        return "mixed"

    @property
    def update_count(self) -> int:
        return max(0, len(self.revisions) - 1)


def _eol_end(data: bytes, pos: int) -> int:
    """Advance past a single EOL (\\r, \\n or \\r\\n) after ``pos``."""
    if data[pos:pos + 2] == b"\r\n":
        return pos + 2
    if data[pos:pos + 1] in (b"\r", b"\n"):
        return pos + 1
    return pos


def _section_end(data: bytes, offset: int) -> int:
    m = _EOF_RE.search(data, offset)
    if not m:
        return len(data)
    return _eol_end(data, m.end())


def _parse_classic(data: bytes, offset: int) -> tuple[int | None, int | None, int, int]:
    """Return (prev, xrefstm, entry_count, trailer_end) for a classic xref table at offset."""
    trailer_pos = data.find(b"trailer", offset)
    if trailer_pos == -1:
        raise ValueError(f"classic xref at {offset} has no trailer")
    table = data[offset + 4:trailer_pos]
    entries = 0
    for m in _SUBSECTION_RE.finditer(table):
        # a subsection header is "start count"; entries themselves are 20-byte rows
        # "nnnnnnnnnn ggggg n" and never match because of the third field.
        line_end = table.find(b"\n", m.start())
        line = table[m.start():line_end if line_end != -1 else None].strip()
        if len(line.split()) == 2:
            entries += int(m.group(2))
    sx = data.find(b"startxref", trailer_pos)
    trailer = data[trailer_pos:sx if sx != -1 else trailer_pos + 4096]
    prev = _PREV_RE.search(trailer)
    stm = _XREFSTM_RE.search(trailer)
    return (int(prev.group(1)) if prev else None,
            int(stm.group(1)) if stm else None,
            entries,
            sx)


def _parse_stream(data: bytes, offset: int) -> int | None:
    """Return /Prev for a cross-reference stream object at offset."""
    stream_kw = data.find(b"stream", offset)
    if stream_kw == -1:
        raise ValueError(f"xref stream at {offset} has no stream keyword")
    header = data[offset:stream_kw]
    if b"/XRef" not in header:
        raise ValueError(f"object at {offset} is not a cross-reference stream")
    prev = _PREV_RE.search(header)
    return int(prev.group(1)) if prev else None


def _resolve_offset(data: bytes, offset: int, header_offset: int) -> int | None:
    """Offsets are nominally from byte 0, but some files have junk before %PDF-."""
    for candidate in (offset, offset + header_offset):
        if not 0 <= candidate < len(data):
            continue
        raw = data[candidate:candidate + 64]
        window = raw.lstrip(_WS)
        skipped = len(raw) - len(window)
        if window.startswith(b"xref"):
            return candidate + skipped
        m = _OBJ_HEADER_RE.match(window)
        if m:
            return candidate + skipped
    return None


def parse(data: bytes) -> RawStructure:
    size = len(data)
    header_offset = data.find(b"%PDF-", 0, 1024)
    header_version = None
    if header_offset != -1:
        m = re.match(rb"%PDF-(\d\.\d)", data[header_offset:header_offset + 8])
        header_version = m.group(1).decode() if m else None
    else:
        header_offset = -1

    linearized = False
    lin_e: int | None = None
    head = data[:2048]
    lm = _LINEARIZED_RE.search(head)
    if lm:
        linearized = True
        e = _LIN_E_RE.search(head, lm.start())
        lin_e = int(e.group(1)) if e else None

    chain_errors: list[str] = []
    sections: list[XrefSection] = []

    last = None
    for m in _STARTXREF_RE.finditer(data):
        last = m
    if last is None:
        # tolerate "startxref N" without %%EOF (truncated files)
        pos = data.rfind(b"startxref")
        if pos != -1:
            mm = re.match(rb"startxref\s+(\d+)", data[pos:pos + 40])
            start = int(mm.group(1)) if mm else None
        else:
            start = None
        chain_errors.append("no 'startxref ... %%EOF' trailer found")
    else:
        start = int(last.group(1))

    visited: set[int] = set()
    offset = start
    while offset is not None and len(sections) < MAX_SECTIONS:
        resolved = _resolve_offset(data, offset, max(header_offset, 0))
        if resolved is None:
            chain_errors.append(f"xref offset {offset} does not point at a cross-reference section")
            break
        if resolved in visited:
            chain_errors.append(f"xref chain loops at offset {resolved}")
            break
        visited.add(resolved)
        window = data[resolved:resolved + 8]
        try:
            if window.startswith(b"xref"):
                prev, stm, entries, _ = _parse_classic(data, resolved)
                sec = XrefSection(resolved, "classic", prev, stm, _section_end(data, resolved), entries)
            else:
                prev = _parse_stream(data, resolved)
                sec = XrefSection(resolved, "stream", prev, None, _section_end(data, resolved))
        except ValueError as exc:
            chain_errors.append(str(exc))
            break
        sections.append(sec)
        offset = sec.prev

    # Linearization: the first-page section sits before /E and is closed by "startxref 0".
    if linearized:
        for sec in sections:
            closing = data.rfind(b"startxref", sec.offset, sec.end)
            closes_with_zero = closing != -1 and re.match(rb"startxref\s+0\s", data[closing:closing + 16])
            if (lin_e is not None and sec.offset < lin_e) or closes_with_zero:
                sec.linearization_first_page = True
                break

    revisions: list[Revision] = []
    for sec in reversed(sections):  # oldest first
        if sec.linearization_first_page:
            continue
        revisions.append(Revision(index=len(revisions) + 1, end=sec.end, sections=[sec]))
    # attach the first-page section to the revision it belongs to (the original one)
    for sec in sections:
        if sec.linearization_first_page and revisions:
            revisions[0].sections.insert(0, sec)
    revisions.sort(key=lambda r: r.end)
    for i, r in enumerate(revisions, 1):
        r.index = i

    eof_count = len(_EOF_RE.findall(data))
    last_eof = data.rfind(b"%%EOF")
    trailing = data[last_eof + 5:] if last_eof != -1 else b""
    stripped = trailing.strip(_WS)
    return RawStructure(
        size=size,
        header_offset=header_offset,
        header_version=header_version,
        linearized=linearized,
        sections=sections,
        revisions=revisions,
        eof_marker_count=eof_count,
        trailing_bytes=len(stripped),
        trailing_preview=stripped[:64].decode("latin-1", errors="replace"),
        chain_errors=chain_errors,
    )
