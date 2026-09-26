"""Minimal synthetic Office Open XML packages for tests (built with zipfile, no Office needed)."""

from __future__ import annotations

import io
import warnings
import zipfile

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_R = "http://schemas.openxmlformats.org/package/2006/relationships"

MAIN = {
    "docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    "xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    "pptx": ("ppt/presentation.xml",
             "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
}


def core_xml(creator="Anna Andersson", last="Anna Andersson", created="2026-03-01T10:00:00Z",
             modified="2026-03-01T11:00:00Z", revision="3", printed: str | None = None) -> str:
    p = f"<cp:lastPrinted>{printed}</cp:lastPrinted>" if printed else ""
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last}</cp:lastModifiedBy>"
            f"<cp:revision>{revision}</cp:revision>{p}"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>'
            "</cp:coreProperties>")


def app_xml(app="Microsoft Office Word", version="16.0000", total_time="12", template="Normal.dotm") -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f"<Template>{template}</Template><TotalTime>{total_time}</TotalTime>"
            f"<Application>{app}</Application><AppVersion>{version}</AppVersion></Properties>")


def word_body(inner: str = "<w:p><w:r><w:t>Invoice total: 100 SEK</w:t></w:r></w:p>") -> str:
    return f'<?xml version="1.0" encoding="UTF-8"?><w:document {W}><w:body>{inner}</w:body></w:document>'


def workbook(sheets=(("Invoice", "visible"),)) -> str:
    items = "".join(
        f'<sheet name="{n}" sheetId="{i}" r:id="rId{i}"' + (f' state="{st}"' if st != "visible" else "") + "/>"
        for i, (n, st) in enumerate(sheets, 1))
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{R_NS}"><sheets>{items}</sheets></workbook>')


def presentation() -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>')


def slide(hidden=False) -> str:
    show = ' show="0"' if hidden else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            f'<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"{show}/>')


def build(kind="docx", *, main: str | None = None, core: str | None = None, app: str | None = None,
          extra: dict[str, bytes | str] | None = None, content_types: bool = True, root_rels: bool = True,
          duplicate: str | None = None) -> bytes:
    main_part, ctype = MAIN[kind]
    if main is None:
        main = {"docx": word_body, "xlsx": workbook, "pptx": presentation}[kind]()
    parts: dict[str, bytes | str] = {main_part: main,
                                     "docProps/core.xml": core if core is not None else core_xml(),
                                     "docProps/app.xml": app if app is not None else app_xml()}
    if content_types:
        parts["[Content_Types].xml"] = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/{main_part}" ContentType="{ctype}"/></Types>')
    if root_rels:
        parts["_rels/.rels"] = (
            f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG_R}">'
            f'<Relationship Id="rId1" Type="{R_NS}/officeDocument" Target="{main_part}"/></Relationships>')
    parts.update(extra or {})
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate-name warning
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in parts.items():
                zf.writestr(name, data)
            if duplicate:
                zf.writestr(duplicate, parts.get(duplicate, "<x/>"))
    return buf.getvalue()


def external_rels(part_rels: str, rel_type: str, target: str) -> dict[str, str]:
    return {part_rels: (f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{PKG_R}">'
                        f'<Relationship Id="rId9" Type="{R_NS}/{rel_type}" Target="{target}" '
                        'TargetMode="External"/></Relationships>')}
