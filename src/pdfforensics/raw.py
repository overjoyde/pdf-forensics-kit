"""Byte-level structure parsing: header, revisions (startxref -> /Prev chain), trailing data.

Upstream counted ``%%EOF`` markers to find incremental updates. That misreads linearized files
(which always have two), and it matches ``%%EOF`` inside streams. Here, revisions come from
the cross-reference chain itself. Each section is found through ``startxref`` and then
``/Prev``, for classic tables and cross-reference streams alike. The linearization
first-page section is merged into the revision it belongs to.

The chain is written by whoever produced the file, so it is not trusted to be complete. A
``startxref ... %%EOF`` that the chain does not reach, but that points at a real
cross-reference section outside any stream, still closes an earlier version of the file. Such
versions are kept as recovered revisions so they are compared like any other.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

_WS = b" \t\r\n\f\x00"
_STARTXREF_RE = re.compile(rb"startxref\s+(\d+)\s+%%EOF")
_OBJ_HEADER_RE = re.compile(rb"\s*(\d+)\s+(\d+)\s+obj")
_PREV_RE = re.compile(rb"/Prev\s+(\d+)")
_XREFSTM_RE = re.compile(rb"/XRefStm\s+(\d+)")
_EOF_RE = re.compile(rb"%%EOF")
_LINEARIZED_RE = re.compile(rb"/Linearized\s")
_FIRST_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_STREAM_START_RE = re.compile(rb">>\s*stream(?:\r\n|\n|\r)")
_DIRECT_LENGTH_RE = re.compile(rb"/Length\s+(\d+)(?!\d)(?!\s+\d+\s+R)")
_LIN_E_RE = re.compile(rb"/E\s+(\d+)")
_SUBSECTION_RE = re.compile(rb"(\d+)\s+(\d+)\s*[\r\n]")

MAX_SECTIONS = 2000
MAX_UNLINKED_CANDIDATES = 4 * MAX_SECTIONS   # startxref markers examined outside the chain
_HEADER_WINDOW = 4096                        # how far back a stream's dictionary is looked for
_XREF_STREAM_WINDOW = 8192                   # how far an xref stream's dictionary may extend


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
    recovered: bool = False  # closed by a startxref/%%EOF the /Prev chain does not reach


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
    def recovered_revisions(self) -> list[Revision]:
        return [r for r in self.revisions if r.recovered]

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


def _linearization(data: bytes, header_offset: int) -> tuple[bool, int | None]:
    """(linearized, /E) from the linearization dictionary, which must be the file's first object.

    The keyword alone proves nothing: it can appear in any string near the start of the file.
    """
    start = max(header_offset, 0)
    m = _FIRST_OBJ_RE.search(data, start, start + 1024)
    if not m:
        return False, None
    end = data.find(b"endobj", m.end(), m.end() + 1024)
    body = data[m.end():end if end != -1 else m.end() + 1024]
    if not body.lstrip(_WS).startswith(b"<<") or not _LINEARIZED_RE.search(body):
        return False, None
    e = _LIN_E_RE.search(body)
    return True, int(e.group(1)) if e else None


def _stream_spans(data: bytes) -> list[tuple[int, int]]:
    """Byte spans of stream data, skipping each stream by its direct /Length where it has one.

    Following /Length (rather than the next "endstream") keeps a PDF carried inside a stream,
    with its own streams and trailers, inside a single span.
    """
    spans: list[tuple[int, int]] = []
    pos = 0
    while True:
        m = _STREAM_START_RE.search(data, pos)
        if not m:
            break
        start = m.end()
        # The dictionary lies between the object header and "stream". Looking back is bounded by
        # the previous stream's end and a fixed window, so the scan stays linear in the file size.
        lo = max(pos, m.start() - _HEADER_WINDOW)
        obj = data.rfind(b"obj", lo, m.start())
        header = data[obj + 3 if obj != -1 else lo:m.start()]
        length = _DIRECT_LENGTH_RE.search(header)
        end = -1
        if length:
            candidate = start + int(length.group(1))
            if data[candidate:candidate + 32].lstrip(_WS).startswith(b"endstream"):
                end = candidate
        if end == -1:
            end = data.find(b"endstream", start)
            if end == -1:
                end = len(data)
        spans.append((start, end))
        pos = max(end, start + 1)
    return spans


def _inside_stream(pos: int, spans: list[tuple[int, int]], starts: list[int]) -> bool:
    i = bisect.bisect_right(starts, pos)
    return i > 0 and pos < spans[i - 1][1]


def _is_xref_section(data: bytes, offset: int) -> bool:
    """A classic table, or an object whose dictionary (within a bounded window) is /XRef."""
    if data[offset:offset + 4] == b"xref":
        return True
    window = data[offset:offset + _XREF_STREAM_WINDOW]
    kw = window.find(b"stream")
    return kw != -1 and _OBJ_HEADER_RE.match(window) is not None and b"/XRef" in window[:kw]


def _near(sorted_values: list[int], value: int, tolerance: int = 4) -> bool:
    i = bisect.bisect_left(sorted_values, value - tolerance)
    return i < len(sorted_values) and sorted_values[i] <= value + tolerance


def _unlinked_ends(data: bytes, sections: list[XrefSection], header_offset: int) -> tuple[list[int], bool]:
    """Ends of earlier file versions closed by a startxref the /Prev chain does not reach.

    Returns (ends, exhausted); exhausted means the candidate budget ran out before the end.
    """
    spans = _stream_spans(data)
    starts = [a for a, _ in spans]
    known_ends = sorted(s.end for s in sections)
    known_offsets = {s.offset for s in sections}
    checked: dict[int, bool] = {}
    found: list[int] = []
    examined = 0
    for m in _STARTXREF_RE.finditer(data):
        end = _eol_end(data, m.end())
        if _near(known_ends, end) or (found and abs(end - found[-1]) <= 4):
            continue
        examined += 1
        if examined > MAX_UNLINKED_CANDIDATES or len(found) >= MAX_SECTIONS:
            return found, True
        if _inside_stream(m.start(), spans, starts):
            continue
        target = _resolve_offset(data, int(m.group(1)), max(header_offset, 0))
        # a target already in the chain is not a separate version (e.g. a PDF attaching itself)
        if target is None or target >= m.start() or target in known_offsets:
            continue
        if target not in checked:
            checked[target] = _is_xref_section(data, target)
        if checked[target]:
            found.append(end)
    return found, False


def parse(data: bytes) -> RawStructure:
    size = len(data)
    header_offset = data.find(b"%PDF-", 0, 1024)
    header_version = None
    if header_offset != -1:
        m = re.match(rb"%PDF-(\d\.\d)", data[header_offset:header_offset + 8])
        header_version = m.group(1).decode() if m else None
    else:
        header_offset = -1

    linearized, lin_e = _linearization(data, header_offset)

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

    # Linearization: the first-page section is the lowest section in the file, sits before /E
    # (or is closed by "startxref 0"), and links forward to the main table with /Prev. An
    # incremental update always links backwards, so it can never qualify.
    if linearized and sections:
        sec = min(sections, key=lambda x: x.offset)
        closing = data.rfind(b"startxref", sec.offset, sec.end)
        closes_with_zero = closing != -1 and re.match(rb"startxref\s+0\s", data[closing:closing + 16])
        # /Prev and /E are written as nominal offsets; resolve them the same way the chain does
        shift = max(header_offset, 0)
        prev = _resolve_offset(data, sec.prev, shift) if sec.prev is not None else None
        links_forward = prev is not None and prev > sec.offset
        before_e = lin_e is not None and sec.offset < lin_e + shift
        if links_forward and (before_e or closes_with_zero):
            sec.linearization_first_page = True

    revisions: list[Revision] = []
    for sec in reversed(sections):  # oldest first
        if sec.linearization_first_page:
            continue
        revisions.append(Revision(index=len(revisions) + 1, end=sec.end, sections=[sec]))
    # attach the first-page section to the revision it belongs to (the original one)
    for sec in sections:
        if sec.linearization_first_page and revisions:
            revisions[0].sections.insert(0, sec)
    unlinked, exhausted = _unlinked_ends(data, sections, header_offset)
    if exhausted:
        chain_errors.append("too many startxref markers outside the chain; not all were examined")
    for end in unlinked:
        revisions.append(Revision(index=0, end=end, recovered=True))
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
