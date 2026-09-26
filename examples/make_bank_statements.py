#!/usr/bin/env python3
"""Generate a FICTITIOUS bank statement and realistically tampered versions of it.

Every document is synthetic: the bank ("Nordbank Demo AB"), the customer, the account number and
the IBAN (check digits 00, so never valid) are invented. Every page carries a "SPECIMEN" watermark
and a footer saying it is a test document.

The story: Erik Exempel applies for a loan with his January 2026 statement. He raises his salary
from 32 450,00 to 52 450,00 SEK and fixes the running balances so the totals still add up.

    python examples/make_bank_statements.py [OUTDIR]      (default: examples/bank-statement)

| File                               | What happened                                                        |
|------------------------------------|----------------------------------------------------------------------|
| 01_original.pdf                    | As issued by the bank's statement engine (control, clean)            |
| 02_original_signed.pdf             | Same, digitally signed by the bank (control, clean: signing is fine) |
| 03_edited_in_acrobat.pdf           | Amounts edited in a desktop editor and saved incrementally           |
| 04_edited_online_editor.pdf        | Edited and re-saved by an online PDF editor (full rewrite)           |
| 05_signed_then_edited.pdf          | The signed statement, edited afterwards                              |
| 06_transactions_export.xlsx        | Excel export with an altered amount; the original is kept in a       |
|                                    | very-hidden sheet                                                    |

Requires pikepdf; the signed variants also need pyHanko (pip install -e '.[signatures]').
"""

from __future__ import annotations

import hashlib
import io
import re
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pikepdf
from pikepdf import Array, Dictionary, Name, String

TZ = timezone(timedelta(hours=1))
ISSUED = datetime(2026, 2, 1, 6, 12, 40, tzinfo=TZ)
EDITED = datetime(2026, 9, 18, 21, 47, 5, tzinfo=timezone(timedelta(hours=2)))
PRODUCER = "Nordbank Statement Engine 3.1 (build 2025.11)"
CREATOR = "Nordbank Core Banking / eStatement"

BANK = "Nordbank Demo AB"
HOLDER = ("Erik Exempel", "Testgatan 12", "123 45 Exempelstad")
ACCOUNT = "9999-12 345 678"
IBAN = "SE00 9999 0000 0012 3456 7800"

OPENING = 18_240.55
# (date, description, amount)   - salary is the line that gets tampered with
TRANSACTIONS = [
    ("2026-01-02", "Hyra Bostads AB januari", -9_850.00),
    ("2026-01-03", "ICA Supermarket Exempelstad", -612.40),
    ("2026-01-05", "Swish Anna Andersson", -350.00),
    ("2026-01-07", "SL Månadskort", -1_060.00),
    ("2026-01-09", "Elbolaget Norden AB", -742.18),
    ("2026-01-12", "Coop Konsum", -489.95),
    ("2026-01-14", "Netflix", -149.00),
    ("2026-01-16", "Swish från Karin Exempel", 500.00),
    ("2026-01-19", "Apotek Hjärtat", -238.50),
    ("2026-01-21", "Kortköp Restaurang Sjöbris", -684.00),
    ("2026-01-23", "Försäkring Trygg Hem", -412.00),
    ("2026-01-25", "Lön Exempelföretaget AB", 32_450.00),
    ("2026-01-26", "Överföring sparkonto", -5_000.00),
    ("2026-01-28", "Telia mobil", -399.00),
    ("2026-01-30", "Kortköp Clas Ohlson", -1_249.00),
]
SALARY_ORIGINAL, SALARY_FAKE = 32_450.00, 52_450.00

# Helvetica AFM widths (1/1000 em) for the characters that are right-aligned
_W = {**{d: 556 for d in "0123456789"}, " ": 278, ",": 278, ".": 278, "-": 333, "+": 584, "S": 667,
      "E": 667, "K": 667}


def sek(v: float) -> str:
    s = f"{abs(v):,.2f}".replace(",", " ").replace(".", ",")
    return ("-" if v < 0 else "") + s


def width(text: str, size: float) -> float:
    return sum(_W.get(ch, 556) for ch in text) * size / 1000


def esc(text: str) -> bytes:
    raw = text.encode("cp1252")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def rows(salary: float) -> list[tuple[str, str, float, float]]:
    bal, out = OPENING, []
    for d, text, amt in TRANSACTIONS:
        if text.startswith("Lön"):
            amt = salary
        bal = round(bal + amt, 2)
        out.append((d, text, amt, bal))
    return out


def page_content(salary: float, invisible_original: bool = False) -> bytes:
    """Build the page content stream. With invisible_original=True the original amounts are left
    underneath as invisible text (render mode 3), a leftover some editors produce."""
    c: list[bytes] = []

    def text(x, y, s, size=9, font="F1", right=False, mode=0):
        if right:
            x -= width(s, size)
        c.append(b"BT /%s %g Tf %d Tr %.2f %.2f Td (" % (font.encode(), size, mode, x, y) + esc(s) + b") Tj ET")

    # watermark
    c.append(b"q 0.92 g BT /F2 90 Tf 0.707 0.707 -0.707 0.707 150 250 Tm (SPECIMEN) Tj ET Q")
    # header band + logo block
    c.append(b"q 0.05 0.23 0.42 rg 40 770 515 42 re f Q")
    c.append(b"q 1 g BT /F2 20 Tf 52 784 Td (" + esc("NORDBANK") + b") Tj ET Q")
    c.append(b"q 1 g BT /F1 8 Tf 430 792 Td (" + esc(BANK) + b") Tj ET Q")
    c.append(b"q 1 g BT /F1 8 Tf 430 781 Td (" + esc("Kontoutdrag / Account statement") + b") Tj ET Q")
    y = 740
    for i, line in enumerate(HOLDER):
        text(52, y - i * 12, line, 10, "F2" if i == 0 else "F1")
    for i, (k, v) in enumerate([("Konto", ACCOUNT), ("IBAN", IBAN), ("Period", "2026-01-01 – 2026-01-31"),
                                ("Utskriven", ISSUED.strftime("%Y-%m-%d"))]):
        text(330, y - i * 12, k, 9, "F2")
        text(390, y - i * 12, v, 9)
    # table header
    ty = 668
    c.append(b"q 0.93 g 40 %d 515 16 re f Q" % (ty - 4))
    text(46, ty, "Datum", 9, "F2")
    text(115, ty, "Text", 9, "F2")
    text(470, ty, "Belopp", 9, "F2", right=True)
    text(549, ty, "Saldo", 9, "F2", right=True)
    ly = ty - 20
    text(115, ly, "Ingående saldo", 9, "F2")
    text(549, ly, sek(OPENING), 9, "F2", right=True)
    orig = rows(SALARY_ORIGINAL)
    for i, (d, t, amt, bal) in enumerate(rows(salary)):
        yy = ly - 16 * (i + 1)
        if i % 2:
            c.append(b"q 0.975 g 40 %.2f 515 16 re f Q" % (yy - 4))
        text(46, yy, d, 9)
        text(115, yy, t, 9)
        text(470, yy, sek(amt), 9, right=True)
        text(549, yy, sek(bal), 9, right=True)
        if invisible_original and (orig[i][2] != amt or orig[i][3] != bal):
            text(470, yy, sek(orig[i][2]), 9, right=True, mode=3)
            text(549, yy, sek(orig[i][3]), 9, right=True, mode=3)
    closing = rows(salary)[-1][3]
    fy = ly - 16 * (len(TRANSACTIONS) + 1) - 6
    c.append(b"q 0.4 G 0.6 w 40 %.2f m 555 %.2f l S Q" % (fy + 12, fy + 12))
    text(115, fy, "Utgående saldo", 9, "F2")
    text(549, fy, sek(closing), 9, "F2", right=True)
    ins = sum(a for _, _, a, _ in rows(salary) if a > 0)
    outs = sum(a for _, _, a, _ in rows(salary) if a < 0)
    text(115, fy - 14, "Summa insättningar", 9)
    text(549, fy - 14, sek(ins), 9, right=True)
    text(115, fy - 28, "Summa uttag", 9)
    text(549, fy - 28, sek(outs), 9, right=True)
    if invisible_original:
        o_close = orig[-1][3]
        text(549, fy, sek(o_close), 9, "F2", right=True, mode=3)
        text(549, fy - 14, sek(sum(a for _, _, a, _ in orig if a > 0)), 9, right=True, mode=3)
    # footer
    text(52, 60, f"{BANK} · Box 000 · 999 99 Exempelstad · Org.nr 000000-0000 · nordbank.example", 7)
    text(52, 48, "SPECIMEN - fictitious test document generated by pdf-forensics-kit. "
                 "Not a real bank, customer or account.", 7, "F2")
    text(549, 48, "Sida 1 av 1", 7, right=True)
    return b"\n".join(c)


def pdf_date(dt: datetime) -> str:
    off = dt.utcoffset() or timedelta(0)
    m = int(off.total_seconds() // 60)
    return dt.strftime("D:%Y%m%d%H%M%S") + f"{'+' if m >= 0 else '-'}{abs(m) // 60:02d}'{abs(m) % 60:02d}'"


def build_original() -> bytes:
    pdf = pikepdf.new()
    enc = Name.WinAnsiEncoding
    f1 = pdf.make_indirect(Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica, Encoding=enc))
    f2 = pdf.make_indirect(Dictionary(Type=Name.Font, Subtype=Name("/Type1"), BaseFont=Name("/Helvetica-Bold"),
                                      Encoding=enc))
    page = pikepdf.Page(Dictionary(Type=Name.Page, MediaBox=Array([0, 0, 595, 842]),
                                   Contents=pdf.make_stream(page_content(SALARY_ORIGINAL)),
                                   Resources=Dictionary(Font=Dictionary(F1=f1, F2=f2))))
    pdf.pages.append(page)
    pdf.docinfo["/Title"] = "Kontoutdrag 2026-01 " + ACCOUNT
    pdf.docinfo["/Author"] = BANK
    pdf.docinfo["/Producer"] = PRODUCER
    pdf.docinfo["/Creator"] = CREATOR
    pdf.docinfo["/CreationDate"] = pdf_date(ISSUED)
    pdf.docinfo["/ModDate"] = pdf_date(ISSUED)
    with pdf.open_metadata(set_pikepdf_as_editor=False, update_docinfo=False) as m:
        m["dc:title"] = "Kontoutdrag 2026-01 " + ACCOUNT
        m["xmp:CreateDate"] = ISSUED.isoformat()
        m["xmp:ModifyDate"] = ISSUED.isoformat()
        m["xmp:CreatorTool"] = CREATOR
        m["pdf:Producer"] = PRODUCER
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.disable, compress_streams=True,
             deterministic_id=True)
    return buf.getvalue()


def append_update(data: bytes, objects: dict[int, bytes]) -> bytes:
    """Append a classic incremental update, the way desktop editors save ("Save", not "Save as")."""
    prev = int(re.findall(rb"startxref\s+(\d+)\s+%%EOF", data)[-1])
    tail = data[prev:]
    size = int(re.search(rb"/Size\s+(\d+)", tail).group(1))
    root = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", tail).group(1)
    info = re.search(rb"/Info\s+(\d+\s+\d+\s+R)", tail)
    ids = re.search(rb"/ID\s*\[\s*(<[0-9a-fA-F]+>)", tail)
    out = bytearray(data if data.endswith(b"\n") else data + b"\n")
    offsets = {}
    for num, body in sorted(objects.items()):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n" + b"".join(b"%d 1\n%010d 00000 n \n" % (n, o) for n, o in sorted(offsets.items()))
    trailer = b"<< /Size %d /Root %s /Prev %d" % (max(size, max(offsets) + 1), root, prev)
    if info:
        trailer += b" /Info " + info.group(1)
    if ids:  # editors keep the permanent ID and write a new second one
        trailer += b" /ID [" + ids.group(1) + b" <" + hashlib.md5(bytes(out)).hexdigest().encode() + b">]"
    out += b"trailer\n" + trailer + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _objnums(data: bytes) -> tuple[int, int]:
    with pikepdf.open(io.BytesIO(data)) as pdf:
        return pdf.pages[0].obj["/Contents"].objgen[0], pdf.trailer["/Info"].objgen[0]


def edit_incrementally(data: bytes) -> bytes:
    """Change the salary and balances, update Info (producer + ModDate) but not XMP, save incrementally."""
    content_num, info_num = _objnums(data)
    import zlib

    stream = zlib.compress(page_content(SALARY_FAKE))
    info = (b"<< /Title (" + esc("Kontoutdrag 2026-01 " + ACCOUNT) + b") /Author (" + esc(BANK) + b")"
            b" /Creator (" + esc(CREATOR) + b") /Producer (Adobe Acrobat Pro \\(64-bit\\) 24.2.20687)"
            b" /CreationDate (" + pdf_date(ISSUED).encode() + b") /ModDate (" + pdf_date(EDITED).encode() + b") >>")
    return append_update(data, {
        content_num: b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream",
        info_num: info,
    })


def edit_online(data: bytes) -> bytes:
    """Re-save through an 'online editor': full rewrite, old amounts left as invisible text."""
    pdf = pikepdf.open(io.BytesIO(data))
    page = pdf.pages[0]
    page.obj.Contents = pdf.make_stream(page_content(SALARY_FAKE, invisible_original=True))
    pdf.docinfo["/Producer"] = "iLovePDF"
    pdf.docinfo["/ModDate"] = pdf_date(EDITED)
    buf = io.BytesIO()
    pdf.save(buf, compress_streams=True)  # XMP untouched: still names the bank's engine
    return buf.getvalue()


def sign(data: bytes) -> bytes:
    from asn1crypto import keys as a_keys
    from asn1crypto import x509 as a_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nordbank Demo eStatement Signing (TEST)"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nordbank Demo AB (fictitious)")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    signer = signers.SimpleSigner(
        signing_cert=a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        signing_key=a_keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore())
    w = IncrementalPdfFileWriter(io.BytesIO(data))
    meta = signers.PdfSignatureMetadata(field_name="NordbankSeal", reason="Utfärdat kontoutdrag",
                                        location="Exempelstad")
    return signers.sign_pdf(w, meta, signer=signer).getvalue()


# ------------------------------------------------------------------------------ Excel export

def _cell(ref: str, v) -> str:
    if isinstance(v, (int, float)):
        return f'<c r="{ref}"><v>{v:.2f}</v></c>'
    t = str(v).replace("&", "&amp;").replace("<", "&lt;")
    return f'<c r="{ref}" t="inlineStr"><is><t>{t}</t></is></c>'


def _sheet(data_rows: list[list]) -> str:
    rows_xml = []
    for r, row in enumerate(data_rows, 1):
        cells = "".join(_cell(f"{'ABCD'[c]}{r}", v) for c, v in enumerate(row))
        rows_xml.append(f'<row r="{r}">{cells}</row>')
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(rows_xml)}</sheetData></worksheet>')


def build_xlsx() -> bytes:
    head = [["Datum", "Text", "Belopp", "Saldo"]]
    orig = head + [[d, t, a, b] for d, t, a, b in rows(SALARY_ORIGINAL)]
    fake = head + [[d, t, a, b] for d, t, a, b in rows(SALARY_FAKE)]
    ns_r = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    ns_p = "http://schemas.openxmlformats.org/package/2006/relationships"
    parts = {
        "[Content_Types].xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/worksheets/sheet2.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/docProps/core.xml" '
            'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>',
        "_rels/.rels":
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{ns_p}">'
            f'<Relationship Id="rId1" Type="{ns_r}/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/'
            'metadata/core-properties" Target="docProps/core.xml"/>'
            f'<Relationship Id="rId3" Type="{ns_r}/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>',
        "xl/workbook.xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{ns_r}"><sheets>'
            '<sheet name="Transaktioner" sheetId="1" r:id="rId1"/>'
            '<sheet name="_export_orig" sheetId="2" state="veryHidden" r:id="rId2"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels":
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{ns_p}">'
            f'<Relationship Id="rId1" Type="{ns_r}/worksheet" Target="worksheets/sheet1.xml"/>'
            f'<Relationship Id="rId2" Type="{ns_r}/worksheet" Target="worksheets/sheet2.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": _sheet(fake),
        "xl/worksheets/sheet2.xml": _sheet(orig),
        "docProps/core.xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<dc:title>Transaktioner 2026-01 (SPECIMEN - fictitious)</dc:title>"
            "<dc:creator>Nordbank eStatement Export</dc:creator><cp:lastModifiedBy>Erik Exempel</cp:lastModifiedBy>"
            "<cp:revision>4</cp:revision>"
            '<dcterms:created xsi:type="dcterms:W3CDTF">2026-02-01T05:12:40Z</dcterms:created>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-09-18T19:51:12Z</dcterms:modified>'
            "</cp:coreProperties>",
        "docProps/app.xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            "<Application>Microsoft Excel</Application><AppVersion>16.0300</AppVersion>"
            "<TotalTime>3</TotalTime><Company>Nordbank Demo AB</Company></Properties>",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, d in parts.items():
            zf.writestr(n, d)
    return buf.getvalue()


def generate(outdir: Path, with_signatures: bool = True) -> dict[str, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    files: dict[str, bytes] = {}
    original = build_original()
    files["01_original.pdf"] = original
    files["03_edited_in_acrobat.pdf"] = edit_incrementally(original)
    files["04_edited_online_editor.pdf"] = edit_online(original)
    if with_signatures:
        signed = sign(original)
        files["02_original_signed.pdf"] = signed
        files["05_signed_then_edited.pdf"] = edit_incrementally(signed)
    files["06_transactions_export.xlsx"] = build_xlsx()
    paths = {}
    for name, data in sorted(files.items()):
        p = outdir / name
        p.write_bytes(data)
        paths[name] = p
    return paths


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "bank-statement"
    try:
        import pyhanko.sign  # noqa: F401
        have_sig = True
    except ImportError:
        have_sig = False
        print("pyHanko not installed: skipping the signed variants", file=sys.stderr)
    for name, path in generate(target, have_sig).items():
        print(f"{path}  ({path.stat().st_size:,} bytes)")
