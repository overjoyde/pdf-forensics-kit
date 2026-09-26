"""Active and external content: JavaScript, launch/submit actions, embedded files, XFA, URIs.

Scans every object (all generations, object-stream members included), not only the catalog,
so actions hidden in annotations, pages, form fields or name trees are found.
"""

from __future__ import annotations

from collections import defaultdict

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import get, iter_objects, name, s

E_INVOICE_NAMES = ("factur-x.xml", "zugferd-invoice.xml", "zugferd.xml", "xrechnung.xml", "order-x.xml")
MAX_NESTING = 12


def _iter_dicts(obj, depth: int = 0):
    """Yield obj and every *direct* dictionary nested inside it.

    Actions and file specifications are often direct objects inside an annotation's /A,
    a name-tree /Names array or an /AA dictionary. Indirect children are not followed here
    because they are visited as objects in their own right.
    """
    if depth > MAX_NESTING:
        return
    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
        yield obj
        children = [obj[k] for k in list(obj.keys())]
    elif isinstance(obj, pikepdf.Array):
        children = list(obj)
    else:
        return
    for c in children:
        try:
            if isinstance(c, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)) and not c.is_indirect:
                yield from _iter_dicts(c, depth + 1)
        except Exception:
            continue


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="active_content")
    hits: dict[str, list[str]] = defaultdict(list)
    uris: list[str] = []
    embedded: list[str] = []

    objs, status = iter_objects(doc.pdf, doc.options.max_objects)

    def candidates():
        for top in objs:
            if not isinstance(top, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                continue
            try:
                top_ref = f"{top.objgen[0]} {top.objgen[1]} R"
                for d in _iter_dicts(top):
                    yield d, top_ref if d is top or d.is_indirect else f"inside {top_ref}"
            except Exception:
                continue

    for obj, ref in candidates():
        try:
            action = name(get(obj, "/S"))
            if action == "/JavaScript" or "/JS" in obj:
                hits["javascript"].append(ref)
            if action == "/Launch":
                hits["launch"].append(ref)
            if action in ("/SubmitForm", "/ImportData"):
                hits["submit_import"].append(f"{ref} {action}")
            if action in ("/GoToR", "/GoToE"):
                hits["remote_goto"].append(f"{ref} {action}")
            if action in ("/RichMediaExecute", "/Rendition", "/Movie", "/Sound"):
                hits["multimedia"].append(f"{ref} {action}")
            if name(get(obj, "/Subtype")) in ("/RichMedia", "/Movie", "/Screen", "/3D"):
                hits["multimedia"].append(f"{ref} {name(get(obj, '/Subtype'))}")
            if action == "/URI":
                u = s(get(obj, "/URI"), 300)
                if u and u not in uris:
                    uris.append(u)
            if "/AA" in obj:
                hits["additional_actions"].append(ref)
            # /EF must be a dictionary: in UR3 TransformParams /EF is a permissions *array*
            if isinstance(get(obj, "/EF"), pikepdf.Dictionary):
                fname = s(get(obj, "/UF") or get(obj, "/F"), 200)
                if (fname or ref) not in embedded:
                    embedded.append(fname or ref)
        except Exception:
            continue

    root = doc.pdf.Root
    open_action = get(root, "/OpenAction")
    if open_action is not None:
        act = name(get(open_action, "/S")) if isinstance(open_action, pikepdf.Dictionary) else "/GoTo (destination)"
        res.facts["open_action"] = act
    names = get(root, "/Names")
    if names is not None and get(names, "/JavaScript") is not None:
        hits["javascript"].append("catalog /Names /JavaScript")
    acro = get(root, "/AcroForm")
    has_xfa = acro is not None and get(acro, "/XFA") is not None

    res.facts.update({
        "javascript": hits["javascript"][:50], "launch": hits["launch"][:50],
        "submit_import": hits["submit_import"][:50], "remote_goto": hits["remote_goto"][:50],
        "multimedia": hits["multimedia"][:50], "additional_actions": hits["additional_actions"][:50],
        "embedded_files": embedded[:100], "uris": uris[:100], "xfa": has_xfa,
        "objects_scan_truncated": status["truncated"],
    })

    def add(fid, title, sev, conf, expl, ev, benign=()):
        res.findings.append(Finding(fid, title, sev, conf, "active-content", expl, ev, list(benign)))

    if hits["launch"]:
        add("active.launch-action", "Launch action (can start external programs)", Severity.HIGH, Confidence.HIGH,
            "A /Launch action asks the viewer to open a file or run a program. Legitimate documents almost never need this.",
            {"objects": hits["launch"][:20]})
    if hits["javascript"]:
        add("active.javascript", "Embedded JavaScript", Severity.HIGH if open_action is not None else Severity.MEDIUM,
            Confidence.HIGH,
            "JavaScript can change what fields and pages show at open time, dynamically, and is a common malware vector.",
            {"objects": hits["javascript"][:20], "open_action": res.facts.get("open_action")},
            ["Interactive forms that use JavaScript for field calculations or validation"])
    if hits["submit_import"]:
        add("active.submit-or-import", "Form submit / data import actions", Severity.MEDIUM, Confidence.HIGH,
            "The document can send field data to a URL or pull external data into its fields.",
            {"actions": hits["submit_import"][:20]}, ["Online application forms"])
    if hits["remote_goto"]:
        add("active.remote-goto", "Links to other/embedded PDF documents", Severity.LOW, Confidence.HIGH,
            "GoToR/GoToE actions open another file.", {"actions": hits["remote_goto"][:20]})
    if hits["multimedia"]:
        add("active.multimedia", "Rich media / multimedia content", Severity.LOW, Confidence.HIGH,
            "Multimedia annotations execute players inside the viewer.", {"objects": hits["multimedia"][:20]})
    if has_xfa:
        add("active.xfa", "XFA form", Severity.MEDIUM, Confidence.HIGH,
            ("XFA forms are rendered from an XML template, not from the page content. Different viewers can show "
             "different content, and text extraction can miss what is displayed."),
            {}, ["Enterprise forms from Adobe LiveCycle / AEM"])
    if embedded:
        einv = [e for e in embedded if e.lower() in E_INVOICE_NAMES]
        other = [e for e in embedded if e not in einv]
        if einv:
            add("active.e-invoice-attachment", "Structured e-invoice attachment", Severity.INFO, Confidence.HIGH,
                ("A ZUGFeRD / Factur-X XML invoice is embedded. It is the machine-readable twin of the visible invoice. "
                 "Compare its amounts with the visible page."),
                {"files": einv})
        if other:
            add("active.embedded-files", "Embedded file attachments", Severity.MEDIUM, Confidence.HIGH,
                "The PDF carries attached files. Attachments can contain malware, or other versions of the document.",
                {"files": other[:30]}, ["Supporting documents attached on purpose"])
    if hits["additional_actions"] and not hits["javascript"]:
        add("active.additional-actions", "Additional-action triggers (/AA)", Severity.LOW, Confidence.MEDIUM,
            "/AA dictionaries run actions on events such as page open or field focus.",
            {"objects": hits["additional_actions"][:20]})
    if uris:
        add("active.uris", f"{len(uris)} external link(s)", Severity.INFO, Confidence.HIGH,
            "External URLs referenced by link actions.", {"uris": uris[:50]})
    if status["truncated"]:
        add("analysis.objects-truncated", "Object scan hit the configured limit", Severity.INFO, Confidence.HIGH,
            "Not all objects were scanned for active content; raise --max-objects for full coverage.",
            {"limit": doc.options.max_objects})
    return res
