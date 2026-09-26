"""Optional second signature validator: Poppler ``pdfsig`` (``brew install poppler``).

pdfsig reports signed-content integrity, certificate trust and revocation as separate
states, which are kept separate here. It runs only if it is installed and external tools
are enabled. It never gets network access by default: ``-no-ocsp`` is passed unless
``--online-revocation`` is given. It reads a private temporary copy of the captured bytes,
never the original path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Any

import pikepdf

from pdfforensics.capture import private_copy
from pdfforensics.document import Document
from pdfforensics.model import AnalyzerResult, Confidence, Finding, Severity

TIMEOUT_S = 30
MAX_OUTPUT = 200_000

INTEGRITY = [  # (pattern, state) - first match wins
    (r"signature is valid", "valid"),
    (r"digest mismatch", "invalid"),
    (r"signature is invalid", "invalid"),
    (r"document isn't signed or corrupted", "invalid"),
    (r"not yet been verified", "unknown"),
    (r"unknown validation failure", "unknown"),
]
TRUST = [
    (r"certificate is trusted", "trusted"),
    (r"has been revoked", "revoked"),
    (r"has expired", "expired"),
    (r"issuer isn't trusted", "untrusted"),
    (r"issuer is unknown", "untrusted"),
    (r"not been verified", "not-checked"),
]


def find_pdfsig() -> str | None:
    return shutil.which("pdfsig")


@lru_cache(maxsize=1)
def pdfsig_version(exe: str) -> str | None:
    try:
        out = subprocess.run([exe, "-v"], capture_output=True, text=True, timeout=10,
                             stdin=subprocess.DEVNULL, env=_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"pdfsig version (\S+)", out.stdout + out.stderr)
    return m.group(1) if m else None


def _env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C", "HOME": os.environ.get("HOME", "")}


def _match(line: str, table: list[tuple[str, str]]) -> str:
    low = line.lower()
    for pat, state in table:
        if re.search(pat, low):
            return state
    return "unknown"


def parse_output(text: str) -> dict[str, Any]:
    """Parse pdfsig stdout into per-signature states."""
    low = text.lower()
    if "does not contain any signatures" in low:
        return {"presence": "absent", "signatures": []}
    sigs: list[dict[str, Any]] = []
    blocks = re.split(r"(?m)^Signature #(\d+):\s*$", text)
    # re.split -> [preamble, n1, block1, n2, block2, ...]
    for i in range(1, len(blocks) - 1, 2):
        block = blocks[i + 1]
        s: dict[str, Any] = {"index": int(blocks[i]), "integrity": "unknown", "trust": "not-checked",
                             "covers_whole_document": None}
        for line in block.splitlines():
            line = line.strip().lstrip("- ").strip()
            if ":" in line:
                key, _, val = line.partition(":")
                key_l = key.strip().lower()
                val = val.strip()
                if key_l == "signature field name":
                    s["field"] = val
                elif key_l == "signer certificate common name":
                    s["signer"] = val
                elif key_l == "signing time":
                    s["signing_time"] = val
                elif key_l == "signature type":
                    s["subfilter"] = val
                elif key_l == "signed ranges":
                    s["signed_ranges"] = val
                elif key_l == "signature validation":
                    s["integrity"] = _match(val, INTEGRITY)
                    s["integrity_text"] = val
                elif key_l == "certificate validation":
                    s["trust"] = _match(val, TRUST)
                    s["trust_text"] = val
            elif line.lower() == "total document signed":
                s["covers_whole_document"] = True
            elif line.lower() == "not total document signed":
                s["covers_whole_document"] = False
        sigs.append(s)
    return {"presence": "present" if sigs else "unknown", "signatures": sigs}


def _has_signature_dict(pdf: pikepdf.Pdf) -> bool:
    for obj in pdf.objects:
        try:
            if isinstance(obj, pikepdf.Dictionary) and "/ByteRange" in obj:
                return True
        except Exception:
            continue
    return False


def run_pdfsig(exe: str, data: bytes, online_revocation: bool, password: str = "") -> dict[str, Any]:
    args = [exe]
    if not online_revocation:
        args.append("-no-ocsp")
    if password:
        args += ["-upw", password]
    with private_copy(data) as tmp:
        try:
            out = subprocess.run(args + [str(tmp)], capture_output=True, text=True, timeout=TIMEOUT_S,
                                 stdin=subprocess.DEVNULL, env=_env())
        except subprocess.TimeoutExpired:
            return {"status": "timeout"}
        except OSError as exc:
            return {"status": "error", "error": str(exc)}
    stdout = out.stdout[:MAX_OUTPUT].replace(str(tmp), "<captured copy>")
    parsed = parse_output(stdout)
    parsed.update({"status": "ok", "return_code": out.returncode,
                   "stderr": out.stderr[:2000].strip()})
    return parsed


def analyze(doc: Document) -> AnalyzerResult:
    res = AnalyzerResult(name="pdfsig")
    exe = find_pdfsig()
    res.facts["available"] = bool(exe)
    res.facts["enabled"] = doc.options.external_tools
    if not doc.options.external_tools or not exe or not _has_signature_dict(doc.pdf):
        return res
    res.facts["version"] = pdfsig_version(exe)
    res.facts["online_revocation"] = doc.options.online_revocation
    r = run_pdfsig(exe, doc.data, doc.options.online_revocation, doc.options.password)
    res.facts["result"] = {k: v for k, v in r.items() if k != "stderr"}
    if r.get("status") != "ok":
        res.findings.append(Finding(
            id="pdfsig.error", title="pdfsig could not complete", severity=Severity.INFO,
            confidence=Confidence.HIGH, category="signatures",
            explanation="The optional second signature validator failed to run.", evidence=r))
        return res

    ph = {v.get("field"): v for v in doc._cache.get("pyhanko_results", []) if v.get("field")}
    for s in r["signatures"]:
        label = s.get("field") or f"#{s['index']}"
        ev = {k: s.get(k) for k in ("field", "signer", "signing_time", "subfilter", "signed_ranges",
                                     "integrity_text", "trust_text", "covers_whole_document")}
        if s["integrity"] == "invalid":
            res.findings.append(Finding(
                id="pdfsig.integrity-failure", title=f"pdfsig: signature '{label}' fails integrity validation",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH, category="signatures",
                explanation="Poppler reports a digest mismatch or invalid signature. The signed bytes were altered.",
                evidence=ev))
        elif s["integrity"] == "unknown":
            res.findings.append(Finding(
                id="pdfsig.integrity-unknown", title=f"pdfsig: integrity of signature '{label}' could not be determined",
                severity=Severity.MEDIUM, confidence=Confidence.LOW, category="signatures",
                explanation=("Poppler did not verify this signature, so this validator says nothing about whether the "
                             "signed bytes are intact. A damaged or unsupported signature container causes this."),
                evidence=ev,
                benign_explanations=["Signature format Poppler does not support"]))
        if s["trust"] == "revoked":
            res.findings.append(Finding(
                id="pdfsig.certificate-revoked", title=f"pdfsig: signing certificate for '{label}' is revoked",
                severity=Severity.HIGH, confidence=Confidence.HIGH, category="signatures",
                explanation=("The signer's certificate is revoked. Check whether revocation happened before or after "
                             "the signing time (a trusted timestamp settles this)."),
                evidence=ev))
        elif s["trust"] == "expired":
            res.findings.append(Finding(
                id="pdfsig.certificate-expired", title=f"pdfsig: signing certificate for '{label}' has expired",
                severity=Severity.LOW, confidence=Confidence.HIGH, category="signatures",
                explanation=("An expired certificate is normal for older documents. It matters only if the "
                             "signature was made after expiry."),
                evidence=ev))
        if s["integrity"] == "valid":
            trust_note = {
                "trusted": "The certificate chains to a trust anchor in the local NSS store.",
                "untrusted": ("The certificate is not in the local NSS trust store. That is expected for an empty "
                              "store, and says nothing about whether the bytes were altered."),
            }.get(s["trust"], "Certificate trust was not evaluated.")
            res.findings.append(Finding(
                id="pdfsig.integrity-ok", title=f"pdfsig: signature '{label}' integrity validates",
                severity=Severity.INFO, confidence=Confidence.HIGH, category="signatures",
                explanation="A second, independent validator (Poppler) confirms the signed bytes are unchanged. "
                            + trust_note,
                evidence=ev))
        other = ph.get(s.get("field"))
        if other and "intact" in other and s["integrity"] in ("valid", "invalid"):
            if other["intact"] != (s["integrity"] == "valid"):
                res.findings.append(Finding(
                    id="signature.validators-disagree",
                    title=f"pyHanko and pdfsig disagree about signature '{label}'",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM, category="signatures",
                    explanation=("Two independent validators give different integrity results. This can point to a "
                                 "parser-differential attack or a malformed signature. Inspect it manually."),
                    evidence={"pyhanko_intact": other["intact"], "pdfsig": s["integrity_text"]}))
    return res
