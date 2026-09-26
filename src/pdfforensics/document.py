"""Loading a PDF once, safely, and sharing it with all analysers."""

from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import pikepdf

from pdfforensics import raw

DEFAULT_MAX_BYTES = 200 * 1024 * 1024


class InputError(Exception):
    """The input cannot be analysed at all (not a PDF, too large, unreadable)."""


@dataclass
class Options:
    password: str = ""
    max_pages: int = 500
    max_objects: int = 50_000
    max_revisions: int = 50
    max_bytes: int = DEFAULT_MAX_BYTES


@dataclass
class Document:
    path: Path
    data: bytes
    options: Options
    pdf: pikepdf.Pdf
    open_warnings: list[str]
    raw: raw.RawStructure
    _cache: dict[str, Any] = field(default_factory=dict)

    @cached_property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @cached_property
    def md5(self) -> str:
        return hashlib.md5(self.data, usedforsecurity=False).hexdigest()

    def close(self) -> None:
        self.pdf.close()


def open_bytes(data: bytes, password: str = "") -> tuple[pikepdf.Pdf, list[str]]:
    pdf = pikepdf.open(io.BytesIO(data), password=password, suppress_warnings=True)
    try:
        warnings = [str(w) for w in pdf.get_warnings()]
    except Exception:  # pragma: no cover - older pikepdf
        warnings = []
    return pdf, warnings


def load(path: str | os.PathLike[str], options: Options | None = None) -> Document:
    options = options or Options()
    p = Path(path)
    if not p.is_file():
        raise InputError(f"not a regular file: {p}")
    size = p.stat().st_size
    if size > options.max_bytes:
        raise InputError(f"file is {size / 1e6:.1f} MB, above the {options.max_bytes / 1e6:.0f} MB limit")
    data = p.read_bytes()
    if b"%PDF-" not in data[:1024]:
        raise InputError("no %PDF- header in the first 1024 bytes - not a PDF")
    try:
        pdf, warnings = open_bytes(data, options.password)
    except pikepdf.PasswordError as exc:
        raise InputError("PDF is encrypted with a user password; pass --password") from exc
    except pikepdf.PdfError as exc:
        raise InputError(f"PDF could not be parsed: {exc}") from exc
    return Document(path=p, data=data, options=options, pdf=pdf,
                    open_warnings=warnings, raw=raw.parse(data))
