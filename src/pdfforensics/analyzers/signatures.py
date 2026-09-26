"""Digital signatures: ByteRange coverage (always) and cryptographic validation (with pyHanko).

Key question for tampering: were bytes added *after* the last signature, and did they change
what the document shows? The revisions analyser answers the second part. Here we establish
coverage and cryptographic integrity.
"""

from __future__ import annotations

import io
import logging
from typing import Any

import pikepdf

from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity
from pdfforensics.pdfutil import get, iso, name, parse_pdf_date, s

try:  # optional dependency
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import SigSeedSubFilter, enumerate_sig_fields
    from asn1crypto import cms
    from pyhanko.sign.validation import EmbeddedPdfSignature, validate_pdf_signature, validate_pdf_timestamp
    from pyhanko.sign.validation.pdf_embedded import extract_contents, extract_signer_info
    from pyhanko_certvalidator import ValidationContext

    HAVE_PYHANKO = True
    logging.getLogger("pyhanko").setLevel(logging.ERROR)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.ERROR)
except Exception:  # pragma: no cover
    HAVE_PYHANKO = False


def _find_signature_dicts(pdf: pikepdf.Pdf) -> list[pikepdf.Dictionary]:
    out = []
    for obj in pdf.objects:
        try:
            if isinstance(obj, pikepdf.Dictionary) and "/ByteRange" in obj and "/Contents" in obj:
                out.append(obj)
        except Exception:
            continue
    return out


def _coverage(sig: pikepdf.Dictionary, data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {
        "object": f"{sig.objgen[0]} {sig.objgen[1]} R" if sig.is_indirect else "direct",
        "type": name(get(sig, "/Type")) or "/Sig",
        "subfilter": name(get(sig, "/SubFilter")),
        "signer_name": s(get(sig, "/Name"), 200),
        "reason": s(get(sig, "/Reason"), 200),
        "location": s(get(sig, "/Location"), 200),
        "signing_time_claimed": iso(parse_pdf_date(s(get(sig, "/M")))),
        "problems": [],
    }
    try:
        br = [int(x) for x in sig["/ByteRange"]]
    except Exception:
        info["problems"].append("ByteRange unreadable")
        return info
    info["byte_range"] = br
    if len(br) != 4:
        info["problems"].append("ByteRange does not have 4 entries")
        return info
    a, b, c, d = br
    end = c + d
    info["signed_end"] = end
    if a != 0:
        info["problems"].append("signed range does not start at byte 0")
    if not (a <= b <= c):
        info["problems"].append("ByteRange segments overlap or are out of order")
    if end > len(data):
        info["problems"].append("ByteRange extends past the end of the file")
    gap = data[a + b:c] if c <= len(data) else b""
    # the gap must hold exactly the hex-encoded /Contents <...>
    if not (gap.startswith(b"<") and gap.rstrip().endswith(b">")):
        info["problems"].append("unsigned gap is not exactly the /Contents hex string")
    info["bytes_after_signed_range"] = max(0, len(data) - end)
    return info


def _embedded_signatures(reader: Any) -> tuple[list[Any], list[dict[str, Any]]]:
    """Load each signature on its own, so one unparseable signature cannot hide the others.

    pyHanko's reader.embedded_signatures raises on the first bad one. Signatures with a SubFilter
    pyHanko does not support are skipped, as pyHanko does; they are reported as not validated.
    """
    supported = {x.value for x in SigSeedSubFilter}
    loaded, broken = [], []
    for fq_name, sig_obj, sig_field in enumerate_sig_fields(reader, filled_status=True):
        try:
            sig = sig_obj.get_object()
            if str(sig.get("/SubFilter", "")) not in supported:
                continue
        except Exception as exc:
            broken.append({"field": str(fq_name), "error": f"{type(exc).__name__}: {exc}"})
            continue
        try:  # the CMS container itself: failing here means it cannot be a valid signature
            extract_signer_info(cms.ContentInfo.load(extract_contents(sig))["content"])
        except Exception as exc:
            broken.append({"field": str(fq_name), "unparseable": True, "error": f"{type(exc).__name__}: {exc}"})
            continue
        try:
            loaded.append(EmbeddedPdfSignature(reader, sig_field, fq_name))
        except Exception as exc:
            broken.append({"field": str(fq_name), "error": f"{type(exc).__name__}: {exc}"})
    loaded.sort(key=lambda e: e.signed_revision)
    return loaded, broken


def _pyhanko_validate(data: bytes, password: str = "") -> list[dict[str, Any]]:
    reader = PdfFileReader(io.BytesIO(data), strict=False)
    if reader.encrypted:
        reader.decrypt(password or "")  # an empty user password opens owner-password-only files
    embedded, results = _embedded_signatures(reader)
    for emb in embedded:
        # plain str: for encrypted files pyHanko hands out decrypted proxy objects
        field_name = getattr(emb, "field_name", None)
        r: dict[str, Any] = {"field": str(field_name) if field_name is not None else None}
        try:
            # No trust anchors on purpose: this checks integrity, not signer trust. Without an explicit
            # list pyHanko falls back to the OS TLS roots, which is deprecated and not a document-signing
            # trust source anyway. Trust is reported by pdfsig against its own store.
            context = ValidationContext(trust_roots=[])
            if emb.sig_object_type == "/DocTimeStamp":
                r["kind"] = "document-timestamp"
                st = validate_pdf_timestamp(emb, validation_context=context)
            else:
                st = validate_pdf_signature(emb, signer_validation_context=context)
            try:
                signer = st.signing_cert.subject.human_friendly
            except Exception:
                signer = ""
            r.update({
                "intact": bool(st.intact),
                "valid": bool(st.valid),
                "trusted": bool(getattr(st, "trusted", False)),
                "coverage": str(getattr(st, "coverage", "")),
                "modification_level": str(getattr(st, "modification_level", "")),
                "docmdp_ok": getattr(st, "docmdp_ok", None),
                "signer": signer,
                "summary": st.summary() if hasattr(st, "summary") else "",
            })
        except Exception as exc:
            r["error"] = f"{type(exc).__name__}: {exc}"
        results.append(r)
    return results


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="signatures")
    sigs = _find_signature_dicts(doc.pdf)
    res.facts["signature_count"] = len(sigs)
    res.facts["pyhanko_available"] = HAVE_PYHANKO
    if not sigs:
        return res

    perms = get(doc.pdf.Root, "/Perms")
    perm_sigs: dict[tuple[int, int], str] = {}
    if isinstance(perms, pikepdf.Dictionary):
        for k in perms.keys():
            v = perms[k]
            if getattr(v, "is_indirect", False):
                perm_sigs[v.objgen] = str(k)
    cov = []
    for sd in sigs:
        c = _coverage(sd, doc.data)
        role = perm_sigs.get(sd.objgen) if sd.is_indirect else None
        if role is None and isinstance(perms, pikepdf.Dictionary):
            # direct /UR3 dictionaries: match on ByteRange
            for k in perms.keys():
                try:
                    if list(perms[k].get("/ByteRange", [])) == list(sd["/ByteRange"]):
                        role = str(k)
                except Exception:
                    pass
        c["purpose"] = {"/UR3": "usage-rights", "/UR": "usage-rights", "/DocMDP": "certification"}.get(
            role or "", "approval" if name(get(sd, "/Type")) != "/DocTimeStamp" else "timestamp")
        cov.append(c)
    res.facts["signatures"] = cov
    ends = [c["signed_end"] for c in cov if "signed_end" in c]
    last_end = max(ends) if ends else None
    tail = doc.data[last_end:] if last_end is not None else b""
    tail_is_ws = tail.strip(b" \r\n\x00") == b""

    for c in cov:
        if c["problems"]:
            res.findings.append(Finding(
                id="signature.malformed-byterange", title=f"Signature {c['object']} has a malformed ByteRange",
                severity=Severity.HIGH, confidence=Confidence.HIGH, category="signatures",
                explanation=("The ByteRange defines which bytes are signed. A malformed range means that the signed "
                             "bytes are not the bytes shown. Known signature-bypass attacks use this."),
                evidence=c))

    if last_end is not None and not tail_is_ws:
        res.findings.append(Finding(
            id="signature.bytes-after-last-signature",
            title=f"{len(tail)} byte(s) were appended after the last signature",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH, category="signatures",
            explanation=("The signature covers the document only up to byte %d. Everything after that was added "
                         "later and is not protected by any signature. See the revisions findings for what those "
                         "later updates changed." % last_end),
            evidence={"last_signed_end": last_end, "file_size": len(doc.data)},
            benign_explanations=["Long-term validation data (DSS) or a document timestamp added after signing",
                                 "Additional signatures by later signers (their own ranges then cover it)"]))

    if HAVE_PYHANKO:
        try:
            ph = _pyhanko_validate(doc.data, doc.options.password)
        except Exception as exc:
            ph = []
            res.facts["pyhanko_error"] = f"{type(exc).__name__}: {exc}"
            res.error = f"pyHanko could not read the signatures: {type(exc).__name__}: {exc}"
        res.facts["validation"] = ph
        doc._cache["pyhanko_results"] = ph  # lets the pdfsig analyser cross-check
        usage_rights = [c for c in cov if c["purpose"] == "usage-rights"]
        if usage_rights:
            res.findings.append(Finding(
                id="signature.usage-rights", title="Reader usage-rights signature (UR3)",
                severity=Severity.INFO, confidence=Confidence.HIGH, category="signatures",
                explanation=("A usage-rights signature unlocks Reader features such as saving filled forms. It is "
                             "applied by the form publisher and does not say who authored or approved the content."),
                evidence={"signatures": [{k: c.get(k) for k in ("object", "subfilter", "byte_range")}
                                         for c in usage_rights]}))
        doc_sigs = [c for c in cov if c["purpose"] != "usage-rights"]
        if len(ph) < len(doc_sigs) and "pyhanko_error" not in res.facts:
            res.findings.append(Finding(
                id="signature.not-validated",
                title=f"{len(doc_sigs) - len(ph)} signature(s) could not be validated cryptographically",
                severity=Severity.LOW, confidence=Confidence.HIGH, category="signatures",
                explanation=("pyHanko skipped these signatures because they use a legacy or unsupported format "
                             "(for example adbe.x509.rsa_sha1) or sit outside the form field tree. Their integrity "
                             "is unknown. Only the ByteRange coverage checks above apply."),
                evidence={"subfilters": sorted({c.get("subfilter") or "?" for c in doc_sigs}),
                          "found": len(doc_sigs), "validated": len(ph)}))
        for r in ph:
            if r.get("unparseable"):
                res.findings.append(Finding(
                    id="signature.unparseable",
                    title=f"Signature '{r.get('field')}' is not a readable signature container",
                    severity=Severity.HIGH, confidence=Confidence.HIGH, category="signatures",
                    explanation=("The signature's /Contents does not hold a well-formed CMS signature, so it cannot be "
                                 "valid. Either the signature was damaged or its bytes were replaced after signing."),
                    evidence=r,
                    benign_explanations=["File corrupted during transfer (check other structural findings)"]))
            elif "error" in r:
                res.findings.append(Finding(
                    id="signature.validation-error", title=f"Signature '{r.get('field')}' could not be validated",
                    severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, category="signatures",
                    explanation="The cryptographic check failed with an error, so integrity is unknown.",
                    evidence=r))
            elif not r["intact"]:
                res.findings.append(Finding(
                    id="signature.broken", title=f"Signature '{r.get('field')}' does not match the signed bytes",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH, category="signatures",
                    explanation="The signed bytes were changed after signing: the cryptographic digest does not match.",
                    evidence=r))
            elif r.get("docmdp_ok") is False or "OTHER" in r.get("modification_level", ""):
                res.findings.append(Finding(
                    id="signature.disallowed-modification",
                    title=f"Changes after signature '{r.get('field')}' go beyond what the signer allowed",
                    severity=Severity.HIGH, confidence=Confidence.HIGH, category="signatures",
                    explanation=("pyHanko's difference analysis found post-signing changes outside form filling, "
                                 "annotations and LTV data, or outside the DocMDP permissions."),
                    evidence=r))
            else:
                res.findings.append(Finding(
                    id="signature.intact", title=f"Signature '{r.get('field')}' is cryptographically intact",
                    severity=Severity.INFO, confidence=Confidence.HIGH, category="signatures",
                    explanation=("The signed bytes are unchanged. Trust in the signer's certificate is a separate "
                                 "question: it needs trust roots, which this tool does not configure by default."),
                    evidence=r))
    else:
        res.findings.append(Finding(
            id="signature.not-validated", title="Signatures present but not cryptographically validated",
            severity=Severity.INFO, confidence=Confidence.HIGH, category="signatures",
            explanation="Install the optional extra: pip install 'pdf-forensics-kit[signatures]'.",
            evidence={"count": len(sigs)}))
    return res
