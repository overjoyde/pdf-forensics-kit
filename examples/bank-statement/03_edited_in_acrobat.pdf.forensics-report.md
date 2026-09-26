# PDF forensic report: 03_edited_in_acrobat.pdf

**Verdict:** `significant-indicators` (level: high)

> Significant indicators of post-creation modification or hidden content.

| Field | Value |
|---|---|
| File | `examples/bank-statement/03_edited_in_acrobat.pdf` |
| Size | 5,343 bytes |
| SHA-256 | `1950a0fb5188533abbde6d2d56ad04b5c59e8b56cade633209032d55fbec4ac4` |
| Analysed (UTC) | 2026-09-26T13:56:16.505686+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Pages | 1 |
| PDF version | 1.3 (xref: classic, linearized: False) |
| Revisions | 2 (1 incremental update(s)) |
| Signatures | 0 |
| Producer / Creator | Adobe Acrobat Pro (64-bit) 24.2.20687 / Nordbank Core Banking / eStatement |
| Pipeline fingerprint | `c7235897064a6eac` (Adobe Acrobat) |

## Summary

**03_edited_in_acrobat.pdf: significant-indicators - 1 finding(s) need attention (1 high).**

1-page PDF 1.3 produced by Adobe Acrobat; 1 later edit(s) appended to the file; not digitally signed.

**Key findings**

- [HIGH] Revision 2 changes page content: removed: "2026-01-25 Lön Exempelföretaget AB 32 450,00 36 602,52" / "2026-01-26 Överföring sparkonto -5 000,00 31 602,52"; added: "2026-01-25 Lön Exempelföretaget AB 52 450,00 56 602,52" / "2026-01-26 Överföring sparkonto -5 000,00 51 602,52" _(benign if: legitimate re-save by an editor after corrections)_

**Checked and found in order**

- No hidden text, print-only annotations or hidden layers.
- No JavaScript, launch actions, form submission or suspicious attachments.
- File structure is sound: no appended or prepended data, and no repairs needed.

**Recommended next steps**

1. Extract the earlier revision(s) with `pdfforensics extract-revisions` and compare them with the current version. Ask the issuer for the original document.
2. To settle the question, use a stronger source than this analysis, in this order: a valid digital signature from a trusted certificate covering the relevant version; a known-good hash from the issuing system or an immutable archive; the source system's audit log or version history; an independently obtained copy from the issuer.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

### [HIGH] Revision 2 changes page content

`revisions.content-changed`, confidence: high, category: revisions

An incremental update replaced or added page content streams, resources or pages. The earlier version is still inside the file and can be extracted with 'pdfforensics extract-revisions'. The visible text differs between the versions (see evidence).

- Evidence:
  - **revision**: `2`
  - **bytes_added**: `1902`
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

### [LOW] Info and XMP modification dates disagree

`metadata.info-xmp-date-mismatch`, confidence: medium, category: metadata

PDFs store dates twice. Tools that edit a file often update only one of them, so a disagreement shows the file was processed by a second tool.

- Evidence:
  - **info**: `2026-09-18T21:47:05+02:00`
  - **xmp**: `2026-02-01T06:12:40+01:00`
  - **difference**: `229 days, 14:34:25`
  - **timezone_exact**: `True`

- Possible benign explanations: Metadata updated by a document management system

### [LOW] Info and XMP disagree on the producing software

`metadata.producer-mismatch`, confidence: medium, category: metadata

Different producers in the two metadata stores mean a second program re-wrote the file.

- Evidence:
  - **info_producer**: `Adobe Acrobat Pro (64-bit) 24.2.20687`
  - **xmp_producer**: `Nordbank Statement Engine 3.1 (build 2025.11)`

## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

