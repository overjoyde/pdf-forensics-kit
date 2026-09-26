"""Synthetic PDF fixtures, built at test time with pikepdf (no binary fixtures in the repo)."""

from __future__ import annotations

import io
import re
import zlib
from datetime import datetime, timedelta, timezone

import pikepdf
from pikepdf import Array, Dictionary, Name, String


def _page(pdf: pikepdf.Pdf, content: bytes, extra_resources: dict | None = None) -> pikepdf.Page:
    font = pdf.make_indirect(Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica))
    resources = Dictionary(Font=Dictionary(F1=font))
    for k, v in (extra_resources or {}).items():
        resources[k] = v
    page = pikepdf.Page(Dictionary(
        Type=Name.Page, MediaBox=Array([0, 0, 595, 842]),
        Contents=pdf.make_stream(content), Resources=resources))
    pdf.pages.append(page)
    return pdf.pages[-1]


def text_stream(*lines: str, render_mode: int = 0) -> bytes:
    parts = [b"BT /F1 12 Tf", b"%d Tr" % render_mode, b"72 760 Td"]
    for line in lines:
        esc = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        parts.append(b"(" + esc.encode("latin-1") + b") Tj 0 -16 Td")
    parts.append(b"ET")
    return b"\n".join(parts)


def pdf_date(dt: datetime) -> str:
    off = dt.utcoffset() or timedelta(0)
    sign = "+" if off >= timedelta(0) else "-"
    mins = abs(int(off.total_seconds() // 60))
    return dt.strftime("D:%Y%m%d%H%M%S") + f"{sign}{mins // 60:02d}'{mins % 60:02d}'"


def build(
    lines=("Invoice 2026-001", "Total: 100 SEK"),
    *,
    producer="Acme Billing 4.2",
    creator="Acme ERP",
    created: datetime | None = None,
    modified: datetime | None = None,
    xmp_create: datetime | None = None,
    render_mode: int = 0,
    linearize: bool = False,
    object_streams: bool = False,
    customize=None,
) -> bytes:
    created = created or datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone(timedelta(hours=1)))
    modified = modified or created
    pdf = pikepdf.new()
    _page(pdf, text_stream(*lines, render_mode=render_mode))
    pdf.docinfo["/Producer"] = producer
    pdf.docinfo["/Creator"] = creator
    pdf.docinfo["/CreationDate"] = pdf_date(created)
    pdf.docinfo["/ModDate"] = pdf_date(modified)
    if xmp_create is not None:
        with pdf.open_metadata(set_pikepdf_as_editor=False, update_docinfo=False) as m:
            m["xmp:CreateDate"] = xmp_create.isoformat()
            m["xmp:ModifyDate"] = modified.isoformat()
            m["pdf:Producer"] = producer
    if customize:
        customize(pdf)
    buf = io.BytesIO()
    pdf.save(buf, linearize=linearize,
             object_stream_mode=pikepdf.ObjectStreamMode.generate if object_streams
             else pikepdf.ObjectStreamMode.disable,
             compress_streams=False, deterministic_id=True)
    return buf.getvalue()


def append_update(data: bytes, new_objects: dict[int, bytes]) -> bytes:
    """Append a classic incremental update that (re)defines the given object numbers."""
    prev = int(re.findall(rb"startxref\s+(\d+)\s+%%EOF", data)[-1])
    tail = data[prev:]
    size = int(re.search(rb"/Size\s+(\d+)", tail).group(1))
    root = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", tail).group(1)
    info = re.search(rb"/Info\s+(\d+\s+\d+\s+R)", tail)
    ids = re.search(rb"/ID\s*\[[^\]]*\]", tail)
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets = {}
    for num, body in sorted(new_objects.items()):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n"
    for num in sorted(offsets):
        out += b"%d 1\n%010d 00000 n \n" % (num, offsets[num])
    new_size = max(size, max(offsets) + 1)
    trailer = b"<< /Size %d /Root %s /Prev %d" % (new_size, root, prev)
    if info:
        trailer += b" /Info " + info.group(1)
    if ids:
        trailer += b" " + ids.group(0)
    trailer += b" >>"
    out += b"trailer\n" + trailer + b"\nstartxref\n%d\n" % xref + b"%%EOF\n"
    return bytes(out)


def append_unlinked_update(data: bytes, new_objects: dict[int, bytes]) -> bytes:
    """Append an update with a complete cross-reference table and no /Prev link to the earlier one.

    Readers accept such a file, but the earlier revision is no longer reachable through the chain.
    Only works on files without object streams (every object must have a top-level "N 0 obj").
    """
    tail = data[int(re.findall(rb"startxref\s+(\d+)\s+%%EOF", data)[-1]):]
    root = re.search(rb"/Root\s+\d+\s+\d+\s+R", tail).group(0)
    info = re.search(rb"/Info\s+\d+\s+\d+\s+R", tail)
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    for num, body in sorted(new_objects.items()):
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    offsets = {int(m.group(1)): m.start() for m in re.finditer(rb"(?m)^(\d+) 0 obj", bytes(out))}
    size = max(offsets) + 1
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for num in range(1, size):
        out += (b"%010d 00000 n \n" % offsets[num]) if num in offsets else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d %s" % (size, root) + ((b" " + info.group(0)) if info else b"") + b" >>\n"
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def stream_obj(content: bytes) -> bytes:
    return b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"


def content_objnum(data: bytes) -> int:
    with pikepdf.open(io.BytesIO(data)) as pdf:
        return pdf.pages[0].obj["/Contents"].objgen[0]


def info_objnum(data: bytes) -> int:
    with pikepdf.open(io.BytesIO(data)) as pdf:
        return pdf.trailer["/Info"].objgen[0]


# ------------------------------------------------------------------ customizers

def add_open_action_js(pdf: pikepdf.Pdf) -> None:
    js = pdf.make_indirect(Dictionary(S=Name.JavaScript, JS=String("app.alert('hi');")))
    pdf.Root.OpenAction = js


def add_hidden_layer(pdf: pikepdf.Pdf) -> None:
    ocg = pdf.make_indirect(Dictionary(Type=Name.OCG, Name=String("Original amount")))
    pdf.Root.OCProperties = Dictionary(OCGs=Array([ocg]), D=Dictionary(OFF=Array([ocg]), Order=Array([ocg])))


def add_scan_image(pdf: pikepdf.Pdf) -> None:
    raw = bytes([200]) * (100 * 100)
    img = pdf.make_stream(zlib.compress(raw), Type=Name.XObject, Subtype=Name.Image, Width=100, Height=100,
                          ColorSpace=Name.DeviceGray, BitsPerComponent=8, Filter=Name.FlateDecode)
    page = pdf.pages[0]
    page.obj.Resources.XObject = Dictionary(Im1=img)
    old = page.obj.Contents.read_bytes()
    page.obj.Contents = pdf.make_stream(b"q 595 0 0 842 0 0 cm /Im1 Do Q\n" + old)


def add_invisible_text_in_xobject(pdf: pikepdf.Pdf) -> None:
    page = pdf.pages[0]
    form = pdf.make_stream(b"BT /F1 10 Tf 3 Tr 72 100 Td (hidden account 1234) Tj ET",
                           Type=Name.XObject, Subtype=Name.Form, BBox=Array([0, 0, 595, 842]),
                           Resources=Dictionary(Font=page.obj.Resources.Font))
    page.obj.Resources.XObject = Dictionary(Fx1=form)
    old = page.obj.Contents.read_bytes()
    page.obj.Contents = pdf.make_stream(old + b"\nq /Fx1 Do Q")


def add_print_only_annotation(pdf: pikepdf.Pdf) -> None:
    annot = pdf.make_indirect(Dictionary(Type=Name.Annot, Subtype=Name.FreeText, Rect=Array([72, 72, 300, 100]),
                                         Contents=String("PAID"), F=4 | 32, DA=String("/Helv 12 Tf 0 g")))
    pdf.pages[0].obj.Annots = Array([annot])


def add_embedded_file(pdf: pikepdf.Pdf) -> None:
    fs = pikepdf.AttachedFileSpec(pdf, b"payload", filename="notes.txt")
    pdf.attachments["notes.txt"] = fs


def add_link_with_direct_js_action(pdf: pikepdf.Pdf) -> None:
    """JavaScript as a *direct* action dict inside a link annotation (missed by top-level scans)."""
    annot = pdf.make_indirect(Dictionary(Type=Name.Annot, Subtype=Name.Link, Rect=Array([0, 0, 100, 20]),
                                         A=Dictionary(S=Name.JavaScript, JS=String("this.print();"))))
    pdf.pages[0].obj.Annots = Array([annot])


def add_direct_filespec_attachment(pdf: pikepdf.Pdf) -> None:
    """Name-tree attachment whose file specification is a direct dictionary (py-pdf sample style)."""
    ef = pdf.make_stream(b"secret", Type=Name.EmbeddedFile)
    pdf.Root.Names = Dictionary(EmbeddedFiles=Dictionary(Names=Array([
        String("image.png"), Dictionary(Type=Name.Filespec, F=String("image.png"), EF=Dictionary(F=ef))])))


def with_orphan(data: bytes, body: bytes) -> bytes:
    """Add an unreferenced object (qpdf drops orphans on save, so append it as an update)."""
    size = int(re.findall(rb"/Size\s+(\d+)", data)[-1])
    return append_update(data, {size: body})


ORPHAN_TEXT = stream_obj(b"BT /F1 12 Tf 72 700 Td (Total: 100 SEK) Tj ET")
ORPHAN_FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"


# ------------------------------------------------------------------ signing (pyHanko)

def corrupt_first_signature(data: bytes) -> bytes:
    """Overwrite the first signature's CMS container with zeros (same length, so offsets hold)."""
    m = re.search(rb"/Contents\s*<([0-9a-fA-F]+)>", data)
    return data[:m.start(1)] + b"30" + b"0" * (len(m.group(1)) - 2) + data[m.end(1):]


def corrupt_last_signature(data: bytes) -> bytes:
    """Like corrupt_first_signature, for the newest signature (no later signature covers it)."""
    m = list(re.finditer(rb"/Contents\s*<([0-9a-fA-F]+)>", data))[-1]
    return data[:m.start(1)] + b"30" + b"0" * (len(m.group(1)) - 2) + data[m.end(1):]


def _test_certificate(common_name: str, timestamping: bool = False):
    from asn1crypto import keys as a_keys
    from asn1crypto import x509 as a_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30)))
    if timestamping:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    else:
        builder = (builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(True, True, False, False, False, True, True, False, False),
                                  critical=True))
    cert = builder.sign(key, hashes.SHA256())
    return (a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
            a_keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())))


def sign(data: bytes, field_name: str = "Sig1", encrypted: bool = False) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    cert, key = _test_certificate("Test Signer")
    signer = signers.SimpleSigner(signing_cert=cert, signing_key=key, cert_registry=SimpleCertificateStore())
    w = IncrementalPdfFileWriter(io.BytesIO(data))
    if encrypted:
        w.encrypt("")  # empty user password: anyone can open it
    out = signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=field_name), signer=signer)
    return out.getvalue()


def document_timestamp(data: bytes) -> bytes:
    """Append an RFC 3161 document timestamp (/DocTimeStamp), as PAdES-LTA archiving does."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    cert, key = _test_certificate("Test TSA", timestamping=True)
    w = IncrementalPdfFileWriter(io.BytesIO(data))
    return signers.PdfTimeStamper(DummyTimeStamper(tsa_cert=cert, tsa_key=key)).timestamp_pdf(
        w, md_algorithm="sha256").getvalue()


def add_empty_signature_field(data: bytes, name: str) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields

    w = IncrementalPdfFileWriter(io.BytesIO(data))
    fields.append_signature_field(w, fields.SigFieldSpec(sig_field_name=name, box=(10, 10, 100, 40)))
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def owner_password_only(data: bytes) -> bytes:
    """Encrypt with an owner password and an empty user password (opens without a password)."""
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(data)) as pdf:
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner", user="", R=6))
    return out.getvalue()
