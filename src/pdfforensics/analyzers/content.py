"""Page-level hiding techniques: invisible text, hidden annotations, layers hidden by default.

Content streams are tokenised with pikepdf (not substring-searched), text render mode is
tracked through the q/Q graphics-state stack, and Form XObjects are followed recursively.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import decoded_size, get, name, s

TEXT_SHOW_OPS = {"Tj", "TJ", "'", '"'}
MAX_XOBJECT_DEPTH = 6
MAX_PAGE_CONTENT_BYTES = 64 * 1024 * 1024        # decoded content parsed per page, forms included
MAX_DOCUMENT_CONTENT_BYTES = 256 * 1024 * 1024   # and per document
MAX_OPERANDS = 32                                # operands kept before an operator

# annotation flags (PDF 32000-1 §12.5.3)
F_INVISIBLE, F_HIDDEN, F_PRINT, F_NOVIEW = 1, 2, 4, 32


def _shown_chars(operands: list[Any]) -> int:
    n = 0
    for op in operands:
        if isinstance(op, pikepdf.String):
            n += len(bytes(op))
        elif isinstance(op, pikepdf.Array):
            n += sum(len(bytes(x)) for x in op if isinstance(x, pikepdf.String))
    return n


class _Budget:
    """Decoded bytes the content scan may still parse, and decoded sizes already measured."""

    def __init__(self) -> None:
        self.document = MAX_DOCUMENT_CONTENT_BYTES
        self.sizes: dict[Any, int | None] = {}

    def size(self, st: pikepdf.Stream) -> int | None:
        key = st.objgen if st.is_indirect else None
        if key is not None and key in self.sizes:
            return self.sizes[key]
        size = decoded_size(st, MAX_PAGE_CONTENT_BYTES)
        if key is not None:
            self.sizes[key] = size
        return size

    def charge(self, streams: list[Any], stats: Counter) -> bool:
        total = 0
        for st in streams:
            if isinstance(st, pikepdf.Stream):
                size = self.size(st)
                if size is None:
                    return False
                total += size
        if stats["decoded_bytes"] + total > MAX_PAGE_CONTENT_BYTES or total > self.document:
            return False
        stats["decoded_bytes"] += total
        self.document -= total
        return True


class _Instructions(pikepdf.StreamParser):
    """Hands (operands, operator) to a callback as the stream is parsed, keeping no instruction list.

    pikepdf.parse_content_stream builds Python objects for every token, which costs about a hundred
    times the decoded size in memory.
    """

    def __init__(self, on_instruction: Any) -> None:
        super().__init__()
        self._operands: list[Any] = []
        self._on = on_instruction
        self.errors = 0

    def handle_object(self, obj: Any, offset: int, length: int) -> None:
        if isinstance(obj, pikepdf.Operator):
            operands, self._operands = self._operands, []
            try:
                # latin-1: an operator token in a damaged stream need not be valid UTF-8
                self._on(operands, obj.unparse().decode("latin-1"))
            except Exception:
                self.errors += 1
        elif len(self._operands) < MAX_OPERANDS:
            self._operands.append(obj)

    def handle_eof(self) -> None:
        pass


def _scan_stream(target: Any, resources: Any, stats: Counter, depth: int, seen: set, budget: _Budget) -> None:
    """Accumulate text/image statistics for a page or form XObject."""
    if depth > MAX_XOBJECT_DEPTH:
        stats["depth_limited"] += 1
        return
    if isinstance(target, pikepdf.Page):
        contents = get(target.obj, "/Contents")
        streams = list(contents) if isinstance(contents, pikepdf.Array) else [contents]
    else:
        streams = [target]
    try:
        affordable = budget.charge(streams, stats)
    except Exception:
        stats["unparsable_streams"] += 1
        return
    if not affordable:
        stats["streams_over_limit"] += 1
        return

    tr_stack = [0]
    xobjects = get(resources, "/XObject") if resources is not None else None
    forms: list[pikepdf.Stream] = []

    def step(operands: list[Any], op: str) -> None:
        if op == "q":
            tr_stack.append(tr_stack[-1])
        elif op == "Q":
            if len(tr_stack) > 1:
                tr_stack.pop()
        elif op == "Tr" and operands:
            try:
                tr_stack[-1] = int(operands[0])
            except Exception:
                pass
        elif op in TEXT_SHOW_OPS:
            n = _shown_chars(operands)
            stats["text_chars"] += n
            if tr_stack[-1] == 3:
                stats["invisible_chars"] += n
            elif tr_stack[-1] == 7:
                stats["clip_only_chars"] += n
        elif op == "Do" and operands and xobjects is not None:
            xo = get(xobjects, str(operands[0]))
            if not isinstance(xo, pikepdf.Stream):
                return
            sub = name(get(xo, "/Subtype"))
            if sub == "/Image":
                stats["images"] += 1
                try:
                    stats["image_pixels"] += int(get(xo, "/Width") or 0) * int(get(xo, "/Height") or 0)
                except Exception:
                    pass
            elif sub == "/Form":
                key = xo.objgen if xo.is_indirect else id(xo)
                if key not in seen:
                    seen.add(key)
                    forms.append(xo)

    try:
        parser = _Instructions(step)
        if isinstance(target, pikepdf.Page):
            target.parse_contents(parser)
        else:
            pikepdf.Object._parse_stream(target, parser)  # what parse_content_stream uses for streams
    except Exception:
        stats["unparsable_streams"] += 1
        return
    if parser.errors:
        stats["instruction_errors"] += parser.errors
    for xo in forms:
        stats["form_xobjects"] += 1
        _scan_stream(xo, get(xo, "/Resources") or resources, stats, depth + 1, seen, budget)


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="content")
    pdf = doc.pdf
    pages_info: list[dict[str, Any]] = []
    invisible_pages, ocr_like_pages, hidden_annots, print_only_annots = [], [], [], []
    annot_types: Counter = Counter()
    budget = _Budget()

    for idx, page in enumerate(pdf.pages):
        if idx >= doc.options.max_pages:
            res.facts["pages_truncated"] = True
            break
        stats: Counter = Counter()
        try:
            _scan_stream(page, get(page.obj, "/Resources"), stats, 0, set(), budget)
        except Exception as exc:
            stats["errors"] += 1
            res.facts.setdefault("page_errors", []).append(f"page {idx + 1}: {exc}")
        pno = idx + 1
        info = {"page": pno, **{k: v for k, v in stats.items() if k != "decoded_bytes"}}
        pages_info.append(info)
        if stats["invisible_chars"]:
            entry = {"page": pno, "invisible_chars": stats["invisible_chars"], "text_chars": stats["text_chars"],
                     "images": stats["images"]}
            if stats["images"] and stats["invisible_chars"] >= 0.8 * stats["text_chars"]:
                ocr_like_pages.append(entry)
            else:
                invisible_pages.append(entry)

        annots = get(page.obj, "/Annots")
        if isinstance(annots, pikepdf.Array):
            for a in annots:
                try:
                    sub = name(get(a, "/Subtype")) or "?"
                    annot_types[sub] += 1
                    flags = int(get(a, "/F") or 0)
                    desc = {"page": pno, "subtype": sub, "flags": flags,
                            "contents": s(get(a, "/Contents"), 120)}
                    if sub in ("/Link", "/Popup"):
                        continue
                    if flags & F_NOVIEW and flags & F_PRINT:
                        print_only_annots.append(desc)
                    elif flags & (F_HIDDEN | F_NOVIEW) or (flags & F_INVISIBLE and sub not in ("/Widget",)):
                        hidden_annots.append(desc)
                except Exception:
                    continue

    res.facts.update({"pages": pages_info[:200], "annotation_types": dict(annot_types)})
    over = [p["page"] for p in pages_info if p.get("streams_over_limit")]
    if over:
        res.findings.append(Finding(
            id="content.stream-too-large",
            title=f"Content on {len(over)} page(s) exceeds the decoding budget; not checked for hidden text",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="content",
            explanation=(f"Page content is only parsed up to {MAX_PAGE_CONTENT_BYTES // (1024 * 1024)} MB of decoded "
                         f"data per page and {MAX_DOCUMENT_CONTENT_BYTES // (1024 * 1024)} MB per document. Content "
                         "beyond that, or content that could not be decoded safely, was not parsed, so invisible "
                         "text on these pages was not checked."),
            evidence={"pages": over[:50], "page_limit_bytes": MAX_PAGE_CONTENT_BYTES,
                      "document_limit_bytes": MAX_DOCUMENT_CONTENT_BYTES},
            benign_explanations=["Very complex vector drawing, such as a detailed map or plan"]))

    # optional content hidden by default / different on print
    ocp = get(pdf.Root, "/OCProperties")
    off_layers, print_diff = [], []
    if ocp is not None:
        d = get(ocp, "/D")
        base_off = name(get(d, "/BaseState")) == "/OFF" if d is not None else False
        off = get(d, "/OFF") if d is not None else None
        ocgs = get(ocp, "/OCGs")
        all_ocgs = list(ocgs) if isinstance(ocgs, pikepdf.Array) else []
        off_set = set()
        if isinstance(off, pikepdf.Array):
            off_set = {o.objgen for o in off if getattr(o, "is_indirect", False)}
        for g in all_ocgs:
            try:
                lname = s(get(g, "/Name"), 100)
                is_off = base_off or (g.is_indirect and g.objgen in off_set)
                usage = get(g, "/Usage")
                pstate = name(get(get(usage, "/Print"), "/PrintState")) if usage is not None else ""
                vstate = name(get(get(usage, "/View"), "/ViewState")) if usage is not None else ""
                if is_off:
                    off_layers.append(lname)
                if (pstate and vstate and pstate != vstate) or (is_off and pstate == "/ON"):
                    print_diff.append({"layer": lname, "view": vstate or ("/OFF" if is_off else "/ON"),
                                       "print": pstate})
            except Exception:
                continue
        res.facts["optional_content"] = {"layers": len(all_ocgs), "off_by_default": off_layers,
                                         "view_print_differs": print_diff}

    if invisible_pages:
        res.findings.append(Finding(
            id="content.invisible-text", title="Invisible text on pages without a matching scan image",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, category="content",
            explanation=("Text drawn with render mode 3 is not displayed but is picked up by search, copy/paste and "
                         "automated extraction. It can make a machine read something different from what a person sees."),
            evidence={"pages": invisible_pages[:30]},
            benign_explanations=["Accessibility or search layer added by a generator"]))
    if ocr_like_pages:
        res.findings.append(Finding(
            id="content.ocr-text-layer", title="Invisible OCR text layer over scanned images",
            severity=Severity.INFO, confidence=Confidence.MEDIUM, category="content",
            explanation=("Pages combine images with invisible text, which is the normal structure of OCR'd scans. "
                         "Automated extraction reads the OCR layer, which can differ from the image."),
            evidence={"pages": ocr_like_pages[:30]}))
    if print_only_annots:
        res.findings.append(Finding(
            id="content.print-only-annotations", title="Annotations that appear only when printed",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="content",
            explanation="These annotations are hidden on screen (NoView) but printed, so screen and paper differ.",
            evidence={"annotations": print_only_annots[:30]}))
    if hidden_annots:
        res.findings.append(Finding(
            id="content.hidden-annotations", title="Hidden annotations", severity=Severity.LOW,
            confidence=Confidence.HIGH, category="content",
            explanation="Annotations flagged Hidden/NoView/Invisible are present but not shown.",
            evidence={"annotations": hidden_annots[:30]},
            benign_explanations=["Leftover review comments", "Form helper widgets"]))
    if print_diff:
        res.findings.append(Finding(
            id="content.layer-view-print-differs", title="Layers that differ between screen and print",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="content",
            explanation="Optional content groups are configured so the printed page differs from the on-screen page.",
            evidence={"layers": print_diff[:30]},
            benign_explanations=["Watermarks shown only on print", "Printer marks in prepress files"]))
    elif off_layers:
        res.findings.append(Finding(
            id="content.layers-hidden-by-default", title="Layers hidden by default",
            severity=Severity.LOW, confidence=Confidence.HIGH, category="content",
            explanation="Some optional content layers are switched off when the document opens, so their content is not seen.",
            evidence={"layers": off_layers[:30]},
            benign_explanations=["CAD/engineering drawings", "Alternative language layers"]))
    return res
