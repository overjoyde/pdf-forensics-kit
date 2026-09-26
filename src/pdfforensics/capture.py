"""Evidence capture: read the questioned file exactly once, safely, and hash those bytes.

- Symbolic links are rejected (O_NOFOLLOW + lstat) so the evidence target is unambiguous.
- The file is read through one descriptor. The size and timestamps of that descriptor are
  compared before and after reading, so a file that changes mid-read is rejected.
- Every analyser then works on the captured bytes, never on the path again. External tools get
  a private read-only temporary copy of the same bytes (see ``private_copy``).
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

READ_CHUNK = 1024 * 1024
STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns")


class InputError(Exception):
    """The input cannot be analysed at all (not captured, unsupported, unparsable)."""


CaptureError = InputError


@dataclass(frozen=True)
class Snapshot:
    path: Path
    data: bytes
    sha256: str
    size: int
    mtime_ns: int
    format: str          # "pdf" | "ooxml" | "ole" | "zip" | "unknown"
    suffix: str          # lower-case extension without dot


def detect_format(data: bytes) -> str:
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"  # refined to "ooxml" by the Office analyser once parts are known
    if data.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        return "ole"
    return "unknown"


def capture(path: str | os.PathLike[str], max_bytes: int) -> Snapshot:
    p = Path(path)
    try:
        info = p.lstat()
    except FileNotFoundError as exc:
        raise CaptureError(f"file not found: {p}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise CaptureError("symbolic links are rejected so the evidence target is unambiguous; pass the real file")
    if not stat.S_ISREG(info.st_mode):
        raise CaptureError(f"not a regular file: {p}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise CaptureError(f"cannot open {p}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise CaptureError(f"not a regular file: {p}")
        if before.st_size == 0:
            raise CaptureError("file is empty")
        if before.st_size > max_bytes:
            raise CaptureError(f"file is {before.st_size / 1e6:.1f} MB, above the {max_bytes / 1e6:.0f} MB limit")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise CaptureError("file grew beyond the size limit while being read")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if any(getattr(before, k) != getattr(after, k) for k in STABLE_FIELDS):
        raise CaptureError("file changed while it was being read; capture a stable copy first")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise CaptureError("captured byte count does not match the file size")
    return Snapshot(path=p, data=data, sha256=digest.hexdigest(), size=len(data),
                    mtime_ns=before.st_mtime_ns, format=detect_format(data),
                    suffix=p.suffix.lower().lstrip("."))


def path_still_matches(snap: Snapshot) -> bool:
    """True if the path still points at a file with the captured size and mtime."""
    try:
        st = snap.path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_size == snap.size and st.st_mtime_ns == snap.mtime_ns


@contextmanager
def private_copy(data: bytes, suffix: str = ".pdf") -> Iterator[Path]:
    """Write the captured bytes to a private (0600) temp file for external tools, then delete it."""
    fd, name = tempfile.mkstemp(prefix="pdfforensics-", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(name, 0o400)
        yield Path(name)
    finally:
        try:
            os.chmod(name, 0o600)
            os.unlink(name)
        except OSError:
            pass
