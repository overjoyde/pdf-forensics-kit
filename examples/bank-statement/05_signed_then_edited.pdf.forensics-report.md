# PDF forensic report: 05_signed_then_edited.pdf

**Verdict:** `strong-indicators` (level: critical)

> Strong indicators of manipulation, for example content changed after signing or a broken signature.

| Field | Value |
|---|---|
| File | `examples/bank-statement/05_signed_then_edited.pdf` |
| Size | 12,610 bytes |
| SHA-256 | `1f493ed7e1cf9ac912b95c96b55e73e849e54999d94a940e34ab07120427b026` |
| Analysed (UTC) | 2026-09-26T13:56:16.528210+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Pages | 1 |
| PDF version | 1.3 (xref: classic, linearized: False) |
| Revisions | 3 (2 incremental update(s)) |
| Signatures | 1 |
| Producer / Creator | Adobe Acrobat Pro (64-bit) 24.2.20687 / Nordbank Core Banking / eStatement |
| Pipeline fingerprint | `c7235897064a6eac` (Adobe Acrobat) |

## Summary

**05_signed_then_edited.pdf: strong-indicators - 3 finding(s) need attention (1 critical, 1 high, 1 medium).**

1-page PDF 1.3 produced by Adobe Acrobat; 2 later edit(s) appended to the file; 1 signature(s), 1 with the signed bytes verified intact, but data was added after the last signature.

**Key findings**

- [CRITICAL] Revision 3 changes page content after the document was signed: removed: "2026-01-25 Lön Exempelföretaget AB 32 450,00 36 602,52" / "2026-01-26 Överföring sparkonto -5 000,00 31 602,52"; added: "2026-01-25 Lön Exempelföretaget AB 52 450,00 56 602,52" / "2026-01-26 Överföring sparkonto -5 000,00 51 602,52" _(benign if: legitimate re-save by an editor after corrections)_
- [HIGH] Changes after signature 'NordbankSeal' go beyond what the signer allowed: pyHanko: INTACT:UNTRUSTED,EXTENDED_WITH_OTHER,ILLEGAL_MODIFICATIONS
- [MEDIUM] 1905 byte(s) were appended after the last signature: signed up to byte 10,705 of 12,610 _(benign if: long-term validation data (DSS) or a document timestamp added after signing)_

**Checked and found in order**

- No hidden text, print-only annotations or hidden layers.
- No JavaScript, launch actions, form submission or suspicious attachments.
- File structure is sound: no appended or prepended data, and no repairs needed.

**Recommended next steps**

1. Extract the earlier revision(s) with `pdfforensics extract-revisions` and compare them with the current version. Ask the issuer for the original document.
2. Ask the signer to confirm the post-signing changes, or obtain the signed revision (extract-revisions) as the authoritative version.
3. Check the revision findings to see whether the unsigned additions change visible content or are only validation data.
4. To settle the question, use a stronger source than this analysis, in this order: a valid digital signature from a trusted certificate covering the relevant version; a known-good hash from the issuing system or an immutable archive; the source system's audit log or version history; an independently obtained copy from the issuer.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

### [CRITICAL] Revision 3 changes page content after the document was signed

`revisions.content-changed`, confidence: high, category: revisions

An incremental update replaced or added page content streams, resources or pages. The earlier version is still inside the file and can be extracted with 'pdfforensics extract-revisions'. The visible text differs between the versions (see evidence).

- Evidence:
  - **revision**: `3`
  - **bytes_added**: `1905`
  - **objects_added**: `0`
  - **objects_changed**: `2`
  - **objects_removed**: `0`
  - **changed_roles**: `{"info": 1, "content": 1}`
  - **changed_objects**:
    - `2 0 R`
    - `6 0 R`
  - **text_added**:
    - `page=1, text=2026-01-25 Lön Exempelföretaget AB 52 450,00 56 602,52`
    - `page=1, text=2026-01-26 Överföring sparkonto -5 000,00 51 602,52`
    - `page=1, text=2026-01-28 Telia mobil -399,00 51 203,52`
    - `page=1, text=2026-01-30 Kortköp Clas Ohlson -1 249,00 49 954,52`
    - `page=1, text=Utgående saldo 49 954,52`
    - `page=1, text=Summa insättningar 52 950,00`
  - **text_removed**:
    - `page=1, text=2026-01-25 Lön Exempelföretaget AB 32 450,00 36 602,52`
    - `page=1, text=2026-01-26 Överföring sparkonto -5 000,00 31 602,52`
    - `page=1, text=2026-01-28 Telia mobil -399,00 31 203,52`
    - `page=1, text=2026-01-30 Kortköp Clas Ohlson -1 249,00 29 954,52`
    - `page=1, text=Utgående saldo 29 954,52`
    - `page=1, text=Summa insättningar 32 950,00`

- Possible benign explanations: Legitimate re-save by an editor after corrections; Page added by an approved workflow (e.g. appended cover sheet)

### [HIGH] Changes after signature 'NordbankSeal' go beyond what the signer allowed

`signature.disallowed-modification`, confidence: high, category: signatures

pyHanko's difference analysis found post-signing changes outside form filling, annotations and LTV data, or outside the DocMDP permissions.

- Evidence:
  - **field**: `NordbankSeal`
  - **intact**: `True`
  - **valid**: `True`
  - **trusted**: `False`
  - **coverage**: `SignatureCoverageLevel.ENTIRE_REVISION`
  - **modification_level**: `ModificationLevel.OTHER`
  - **docmdp_ok**: `False`
  - **signer**: `Organization: Nordbank Demo AB (fictitious), Common Name: Nordbank Demo eStatement Signing (TEST)`
  - **summary**: `INTACT:UNTRUSTED,EXTENDED_WITH_OTHER,ILLEGAL_MODIFICATIONS`

### [MEDIUM] 1905 byte(s) were appended after the last signature

`signature.bytes-after-last-signature`, confidence: high, category: signatures

The signature covers the document only up to byte 10705. Everything after that was added later and is not protected by any signature. See the revisions findings for what those later updates changed.

- Evidence:
  - **last_signed_end**: `10705`
  - **file_size**: `12610`

- Possible benign explanations: Long-term validation data (DSS) or a document timestamp added after signing; Additional signatures by later signers (their own ranges then cover it)

### [LOW] Info and XMP modification dates disagree

`metadata.info-xmp-date-mismatch`, confidence: medium, category: metadata

PDFs store dates twice. Tools that edit a file often update only one of them, so a disagreement shows the file was processed by a second tool.

- Evidence:
  - **info**: `2026-09-18T21:47:05+02:00`
  - **xmp**: `2026-09-26T13:06:04+02:00`
  - **difference**: `-8 days, 8:41:01`
  - **timezone_exact**: `True`

- Possible benign explanations: Metadata updated by a document management system

### [LOW] Info and XMP disagree on the producing software

`metadata.producer-mismatch`, confidence: medium, category: metadata

Different producers in the two metadata stores mean a second program re-wrote the file.

- Evidence:
  - **info_producer**: `Adobe Acrobat Pro (64-bit) 24.2.20687`
  - **xmp_producer**: `pyHanko 0.37.0`

### [info] Revision 2 adds a digital signature

`revisions.signature-update`, confidence: high, category: revisions

Signing a PDF always appends an incremental update. On its own this is not a modification.

- Evidence:
  - **revision**: `2`
  - **bytes_added**: `7264`
  - **objects_added**: `3`
  - **objects_changed**: `4`
  - **objects_removed**: `0`
  - **changed_roles**: `{"form": 1, "annotation": 2, "signature": 1, "catalog": 1, "info": 1, "metadata": 1}`
  - **changed_objects**:
    - `10 0 R`
    - `11 0 R`
    - `12 0 R`
    - `1 0 R`
    - `2 0 R`
    - `3 0 R`
    - `5 0 R`

### [info] pdfsig: signature 'NordbankSeal' integrity validates

`pdfsig.integrity-ok`, confidence: high, category: signatures

A second, independent validator (Poppler) confirms the signed bytes are unchanged. The certificate is not in the local NSS trust store. That is expected for an empty store, and says nothing about whether the bytes were altered.

- Evidence:
  - **field**: `NordbankSeal`
  - **signer**: `Nordbank Demo eStatement Signing (TEST)`
  - **signing_time**: `Sep 26 2026 13:06:04`
  - **subfilter**: `adbe.pkcs7.detached`
  - **signed_ranges**: `[0 - 5053], [10119 - 10705]`
  - **integrity_text**: `Signature is Valid.`
  - **trust_text**: `Certificate issuer isn't Trusted.`
  - **covers_whole_document**: `False`

## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

