# PDF forensic report: 02_original_signed.pdf

**Verdict:** `no-indicators` (level: info)

> No indicators of manipulation were found in the checks performed.

| Field | Value |
|---|---|
| File | `examples/bank-statement/02_original_signed.pdf` |
| Size | 10,705 bytes |
| SHA-256 | `0909abde446fa8a34946a113bf51e2e8827ece6b383cb7267db3f51e250b9982` |
| Analysed (UTC) | 2026-09-26T13:56:16.320624+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Pages | 1 |
| PDF version | 1.3 (xref: classic, linearized: False) |
| Revisions | 2 (1 incremental update(s)) |
| Signatures | 1 |
| Producer / Creator | Nordbank Statement Engine 3.1 (build 2025.11); pyHanko 0.37.0 / Nordbank Core Banking / eStatement |
| Pipeline fingerprint | `c6a10d6fe84b6c96` (unclassified) |

## Summary

**02_original_signed.pdf: no-indicators - no significant findings.**

1-page PDF 1.3 produced by Nordbank Statement Engine 3.1 (build 2025.11); pyHanko 0.37.0; 1 later edit(s) appended to the file; 1 signature(s), 1 with the signed bytes verified intact.

**Checked and found in order**

- No page content was changed through appended edits.
- All validated signatures are cryptographically intact.
- No hidden text, print-only annotations or hidden layers.
- No JavaScript, launch actions, form submission or suspicious attachments.
- Metadata dates and producer information are consistent.
- File structure is sound: no appended or prepended data, and no repairs needed.

**Recommended next steps**

1. No action required from the structural analysis. Apply normal business verification (check with the issuer, and compare with known genuine documents) as usual.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

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

### [info] Signature 'NordbankSeal' is cryptographically intact

`signature.intact`, confidence: high, category: signatures

The signed bytes are unchanged. Trust in the signer's certificate is a separate question: it needs trust roots, which this tool does not configure by default.

- Evidence:
  - **field**: `NordbankSeal`
  - **intact**: `True`
  - **valid**: `True`
  - **trusted**: `False`
  - **coverage**: `SignatureCoverageLevel.ENTIRE_FILE`
  - **modification_level**: `ModificationLevel.NONE`
  - **docmdp_ok**: `True`
  - **signer**: `Organization: Nordbank Demo AB (fictitious), Common Name: Nordbank Demo eStatement Signing (TEST)`
  - **summary**: `INTACT:UNTRUSTED,UNTOUCHED`

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
  - **covers_whole_document**: `True`

### [info] A second tool appended its name to the producer

`metadata.producer-extended`, confidence: high, category: metadata

The Info producer extends the XMP producer with another tool's name. Signing and post-processing tools (e.g. pyHanko, Acrobat's signing) commonly do this.

- Evidence:
  - **info_producer**: `Nordbank Statement Engine 3.1 (build 2025.11); pyHanko 0.37.0`
  - **xmp_producer**: `pyHanko 0.37.0`

## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

