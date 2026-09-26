import shutil

import pytest

import pdfgen
from conftest import finding, ids
from pdfforensics.analyzers import pdfsig

SAMPLE_OK = """Digital Signature Info of: <captured copy>
Signature #1:
  - Signature Field Name: Sig1
  - Signer Certificate Common Name: Test Signer
  - Signing Time: Sep 26 2026 12:11:24
  - Signature Type: adbe.pkcs7.detached
  - Signed Ranges: [0 - 1505], [5739 - 6244]
  - Total document signed
  - Signature Validation: Signature is Valid.
  - Certificate Validation: Certificate issuer isn't Trusted.
Signature #2:
  - Signature Field Name: Sig2
  - Signature Type: ETSI.CAdES.detached
  - Not total document signed
  - Signature Validation: Digest Mismatch.
  - Certificate Validation: Certificate has been Revoked.
"""


def test_parse_output_keeps_states_separate():
    p = pdfsig.parse_output(SAMPLE_OK)
    assert p["presence"] == "present"
    s1, s2 = p["signatures"]
    assert (s1["field"], s1["integrity"], s1["trust"], s1["covers_whole_document"]) == ("Sig1", "valid", "untrusted", True)
    assert (s2["integrity"], s2["trust"], s2["covers_whole_document"]) == ("invalid", "revoked", False)


def test_parse_no_signatures():
    assert pdfsig.parse_output("File 'x.pdf' does not contain any signatures\n")["presence"] == "absent"


def test_no_network_by_default(monkeypatch):
    calls = []

    class R:
        returncode, stdout, stderr = 0, SAMPLE_OK, ""

    def fake_run(args, **kw):
        calls.append(args)
        return R()

    monkeypatch.setattr(pdfsig.subprocess, "run", fake_run)
    pdfsig.run_pdfsig("/usr/bin/pdfsig", b"%PDF-1.4", online_revocation=False)
    assert "-no-ocsp" in calls[-1]
    pdfsig.run_pdfsig("/usr/bin/pdfsig", b"%PDF-1.4", online_revocation=True)
    assert "-no-ocsp" not in calls[-1]
    assert "shell" not in str(calls)


needs_pdfsig = pytest.mark.skipif(shutil.which("pdfsig") is None, reason="Poppler pdfsig not installed")


def _signed() -> bytes:
    try:  # importorskip only catches ModuleNotFoundError; uninstall remnants raise plain ImportError
        import pyhanko.sign  # noqa: F401
    except ImportError:
        pytest.skip("pyHanko not installed (needed to create the signed fixture)")
    return pdfgen.sign(pdfgen.build())


@needs_pdfsig
def test_pdfsig_confirms_intact_signature(analyze):
    r = analyze(_signed())
    assert "pdfsig.integrity-ok" in ids(r)
    assert r["tool"]["pdfsig"]
    assert "signature.validators-disagree" not in ids(r)


@needs_pdfsig
def test_pdfsig_detects_altered_signed_bytes(analyze):
    data = bytearray(_signed())
    i = data.find(b"Total: 100")
    data[i + 7:i + 10] = b"999"
    r = analyze(bytes(data))
    assert finding(r, "pdfsig.integrity-failure")["severity"] == "critical"
    assert "signature.broken" in ids(r)          # pyHanko agrees
    assert r["verdict"]["label"] == "strong-indicators"


@needs_pdfsig
def test_external_tools_can_be_disabled(tmp_path):
    from pdfforensics.document import Options
    from pdfforensics.engine import analyze_file
    p = tmp_path / "s.pdf"
    p.write_bytes(_signed())
    r = analyze_file(p, Options(external_tools=False)).to_dict()
    assert not any(i.startswith("pdfsig.") for i in ids(r))
    assert r["tool"]["pdfsig"] is None
