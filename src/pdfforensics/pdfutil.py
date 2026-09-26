"""Small helpers shared by analysers: safe value conversion, PDF dates, object roles."""

from __future__ import annotations

import hashlib
import re
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import pikepdf

# --------------------------------------------------------------------------- values


def s(value: Any, limit: int = 500) -> str:
    """Best-effort string of a PDF value, never raising."""
    if value is None:
        return ""
    try:
        if isinstance(value, pikepdf.String):
            text = str(value)
        elif isinstance(value, pikepdf.Name):
            text = str(value)
        else:
            text = str(value)
    except Exception:
        try:
            text = bytes(value).decode("latin-1", errors="replace")
        except Exception:
            text = repr(value)
    text = text.replace("\x00", "")
    return text if len(text) <= limit else text[:limit] + "…"


def name(value: Any) -> str:
    try:
        return str(value) if isinstance(value, pikepdf.Name) else ""
    except Exception:
        return ""


def get(d: Any, key: str) -> Any:
    try:
        if isinstance(d, (pikepdf.Dictionary, pikepdf.Stream)) and key in d:
            return d[key]
    except Exception:
        return None
    return None


def iter_objects(pdf: pikepdf.Pdf, limit: int) -> tuple[Iterator[pikepdf.Object], dict[str, bool]]:
    """Iterate all objects (every generation, including object-stream members), with a cap.

    Returns the iterator and a status dict whose ``truncated`` flag is set if the cap was hit,
    so callers can report incomplete coverage instead of silently claiming "clean".
    """
    status = {"truncated": False}

    def gen() -> Iterator[pikepdf.Object]:
        for i, obj in enumerate(pdf.objects):
            if i >= limit:
                status["truncated"] = True
                return
            yield obj

    return gen(), status


def object_digest(obj: pikepdf.Object) -> str:
    h = hashlib.sha256()
    try:
        # resolved=True serialises the object body (nested indirect refs stay as "n g R");
        # resolved=False would only give the reference itself.
        h.update(obj.unparse(resolved=True))
    except Exception:
        h.update(repr(obj).encode())
    if isinstance(obj, pikepdf.Stream):
        try:
            h.update(obj.read_raw_bytes())
        except Exception:
            pass
    return h.hexdigest()


# --------------------------------------------------------------------------- bounded stream decoding

_FLATE = {"/FlateDecode", "/Fl"}
# Worst-case expansion per filter, used for chains that are not decoded incrementally here.
_MAX_EXPANSION = {"/ASCIIHexDecode": 1, "/AHx": 1, "/ASCII85Decode": 1, "/A85": 1,
                  "/RunLengthDecode": 128, "/RL": 128, "/LZWDecode": 4096, "/LZW": 4096,
                  "/FlateDecode": 1032, "/Fl": 1032}
_CHUNK = 1 << 16
MAX_FILTERS = 8                                # longer filter chains are not decoded
MAX_DECODED_STREAM_BYTES = 64 * 1024 * 1024    # largest stream an analyser decodes in full
# Other filter chains are handed to qpdf, which decodes them at once. They are only decoded when
# their worst case fits this ceiling; the real size is then checked against the caller's limit.
QPDF_DECODE_CEILING = 256 * 1024 * 1024


class StreamTooLarge(ValueError):
    """The stream decodes, or could decode, to more than can be handled safely."""


def _filters(stream: pikepdf.Stream) -> tuple[list[str], bool]:
    f = stream.get("/Filter")
    names = [str(x) for x in f] if isinstance(f, pikepdf.Array) else ([str(f)] if f is not None else [])
    parms = stream.get("/DecodeParms")
    plist = list(parms) if isinstance(parms, pikepdf.Array) else [parms]
    predictor = False
    for p in plist:
        try:
            predictor = predictor or (isinstance(p, pikepdf.Dictionary) and int(p.get("/Predictor", 1)) > 1)
        except Exception:
            predictor = True
    return names, predictor


def _salvage(d: Any, data: bytes, room: int, keep: bool, out: list[bytes]) -> int:
    """After a zlib error, re-feed the failed window byte by byte to keep the output before the bad byte."""
    produced = 0
    for i in range(len(data)):
        if produced > room or d.eof:
            break
        buf = data[i:i + 1]
        try:
            while buf or not d.eof:
                chunk = d.decompress(buf, min(_CHUNK, room + 1 - produced))
                buf = d.unconsumed_tail
                if not chunk:
                    break
                produced += len(chunk)
                if keep:
                    out.append(chunk)
                if produced > room:
                    break
        except zlib.error:
            break
    return produced


def _inflate(data: bytes, limit: int, keep: bool = True) -> tuple[bytes, int]:
    """Inflate ``data``, producing at most ``limit + 1`` bytes. Returns (output if keep, bytes produced).

    Like qpdf, corrupt input keeps everything decoded before the error; an unreadable zlib header
    raises ValueError, as qpdf does.
    """
    d = zlib.decompressobj()
    out: list[bytes] = []
    produced = 0
    buf = data
    while produced <= limit and not d.eof:
        snapshot = d.copy()
        try:
            chunk = d.decompress(buf, min(_CHUNK, limit + 1 - produced))
        except zlib.error as exc:
            salvaged = _salvage(snapshot, buf, limit - produced, keep, out)
            if produced == 0 and salvaged == 0:
                raise ValueError(f"invalid Flate data: {exc}") from exc
            produced += salvaged
            break
        buf = d.unconsumed_tail
        if not chunk and not buf:
            break
        produced += len(chunk)
        if keep:
            out.append(chunk)
    return b"".join(out), produced


def _flate_only(names: list[str], predictor: bool) -> bool:
    return bool(names) and not predictor and all(n in _FLATE for n in names)


def _worst_case_size(stream: pikepdf.Stream, names: list[str]) -> int:
    raw = stream.read_raw_bytes()
    size = len(raw)
    for i, n in enumerate(names):
        if i == 0 and n in _FLATE:
            size = _inflate(raw, QPDF_DECODE_CEILING, keep=False)[1]
        else:
            size *= _MAX_EXPANSION.get(n, 1)
    return size


def _qpdf_decode(stream: pikepdf.Stream, names: list[str]) -> bytes:
    if _worst_case_size(stream, names) > QPDF_DECODE_CEILING:
        raise StreamTooLarge("filter chain could expand beyond the safe decoding ceiling")
    return stream.read_bytes()


def read_stream(stream: pikepdf.Stream, limit: int) -> tuple[bytes, bool]:
    """Decoded stream data, cut at ``limit`` bytes. Returns (data, truncated).

    Unfiltered and Flate-only streams are decoded incrementally and never beyond ``limit``. Other
    filter chains are decoded by qpdf when their worst case fits QPDF_DECODE_CEILING; otherwise, or
    for chains longer than MAX_FILTERS, StreamTooLarge is raised.
    """
    names, predictor = _filters(stream)
    if len(names) > MAX_FILTERS:
        raise StreamTooLarge(f"{len(names)} filters in one stream")
    if not names:
        raw = stream.read_raw_bytes()
        return raw[:limit], len(raw) > limit
    if _flate_only(names, predictor):
        data, truncated = stream.read_raw_bytes(), False
        for _ in names:
            data, produced = _inflate(data, limit)
            truncated = truncated or produced > limit
        return data[:limit], truncated
    data = _qpdf_decode(stream, names)
    return data[:limit], len(data) > limit


def decoded_size(stream: pikepdf.Stream, cap: int) -> int | None:
    """The stream's decoded size if it is at most ``cap`` bytes, else None. Keeps no decoded data."""
    names, predictor = _filters(stream)
    if len(names) > MAX_FILTERS:
        return None
    try:
        if not names:
            size = len(stream.read_raw_bytes())
        elif _flate_only(names, predictor):
            data, size = stream.read_raw_bytes(), 0
            for i, _ in enumerate(names):
                last = i == len(names) - 1
                data, size = _inflate(data, cap, keep=not last)
                if size > cap:
                    return None
        else:
            size = len(_qpdf_decode(stream, names))
    except StreamTooLarge:
        return None
    return size if size <= cap else None


# --------------------------------------------------------------------------- dates

_PDF_DATE_RE = re.compile(
    r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
    r"\s*(Z|[+\-]\d{2}(?:'?\d{2}'?)?)?"
)


def parse_pdf_date(value: str) -> datetime | None:
    """Parse a PDF date string (``D:YYYYMMDDHHmmSSOHH'mm'``). Naive if no offset is given."""
    if not value:
        return None
    m = _PDF_DATE_RE.match(value.strip())
    if not m:
        return None
    year, mon, day, hh, mm, ss, tz = m.groups()
    try:
        dt = datetime(int(year), int(mon or 1), int(day or 1),
                      int(hh or 0), int(mm or 0), int(ss or 0))
    except ValueError:
        return None
    return _apply_tz(dt, tz)


def _apply_tz(dt: datetime, tz: str | None) -> datetime:
    if not tz:
        return dt
    if tz == "Z":
        return dt.replace(tzinfo=timezone.utc)
    digits = re.sub(r"[^0-9]", "", tz)
    hours = int(digits[:2] or 0)
    minutes = int(digits[2:4] or 0)
    sign = -1 if tz.startswith("-") else 1
    return dt.replace(tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes)))


def parse_xmp_date(value: str) -> datetime | None:
    """Parse an ISO-8601 XMP date (``2024-05-01T10:20:30+02:00``)."""
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        m = re.match(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", v)
        if not m:
            return None
        return datetime(int(m.group(1)), int(m.group(2) or 1), int(m.group(3) or 1))


def date_diff(a: datetime, b: datetime) -> tuple[timedelta, bool]:
    """Return (a - b, exact). If either side lacks a timezone, the result is only exact to ±14h."""
    if (a.tzinfo is None) != (b.tzinfo is None) or a.tzinfo is None:
        return a.replace(tzinfo=None) - b.replace(tzinfo=None), False
    return a - b, True


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


# --------------------------------------------------------------------------- roles

ROLE_PRECEDENCE = [
    "signature", "content", "resource", "annotation", "form", "page",
    "dss", "metadata", "info", "catalog", "structure", "other",
]


def _walk(root: Any, limit: int = 20_000) -> Iterator[pikepdf.Object]:
    """Yield indirect objects reachable from root (bounded, cycle-safe)."""
    stack = [root]
    seen_ids: set[tuple[int, int]] = set()
    steps = 0
    while stack and steps < limit:
        steps += 1
        obj = stack.pop()
        try:
            if obj.is_indirect:
                og = obj.objgen
                if og in seen_ids:
                    continue
                seen_ids.add(og)
                yield obj
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
                for k in list(obj.keys()):
                    if k in ("/Parent", "/P"):
                        continue  # avoid pulling the whole tree back in
                    stack.append(obj[k])
            elif isinstance(obj, pikepdf.Array):
                stack.extend(list(obj))
        except Exception:
            continue


def role_map(pdf: pikepdf.Pdf) -> dict[tuple[int, int], str]:
    """Classify every reachable indirect object by the most specific role it plays."""
    roles: dict[tuple[int, int], set[str]] = {}

    def mark(root: Any, role: str) -> None:
        for o in _walk(root):
            roles.setdefault(o.objgen, set()).add(role)

    try:
        root = pdf.Root
    except Exception:
        return {}
    if root.is_indirect:
        roles.setdefault(root.objgen, set()).add("catalog")
    try:
        info = pdf.trailer.get("/Info")
        if info is not None:
            mark(info, "info")
    except Exception:
        pass
    for key, role in (("/Metadata", "metadata"), ("/DSS", "dss"), ("/AcroForm", "form"),
                      ("/Pages", "structure"), ("/Names", "structure"), ("/OCProperties", "structure")):
        v = get(root, key)
        if v is not None:
            mark(v, role)
    for page in pdf.pages:
        po = page.obj
        if po.is_indirect:
            roles.setdefault(po.objgen, set()).add("page")
        for key, role in (("/Contents", "content"), ("/Resources", "resource"), ("/Annots", "annotation")):
            v = get(po, key)
            if v is not None:
                mark(v, role)
    for og, rs in list(roles.items()):
        try:
            obj = pdf.get_object(og)
            if isinstance(obj, pikepdf.Dictionary) and "/ByteRange" in obj:
                rs.add("signature")
        except Exception:
            pass
    out = {}
    for og, rs in roles.items():
        out[og] = next(r for r in ROLE_PRECEDENCE if r in rs or r == "other")
    return out
