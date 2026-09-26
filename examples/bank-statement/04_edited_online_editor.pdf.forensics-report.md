# PDF forensic report: 04_edited_online_editor.pdf

**Verdict:** `review-recommended` (level: medium)

> Anomalies that need an explanation before relying on the document.

| Field | Value |
|---|---|
| File | `examples/bank-statement/04_edited_online_editor.pdf` |
| Size | 3,459 bytes |
| SHA-256 | `177c72089bed6f957b0e9ba46a56ae34aeb2fd31e0b2180b57f907366aec13de` |
| Analysed (UTC) | 2026-09-26T13:56:16.516012+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Pages | 1 |
| PDF version | 1.3 (xref: classic, linearized: False) |
| Revisions | 1 (0 incremental update(s)) |
| Signatures | 0 |
| Producer / Creator | iLovePDF / Nordbank Core Banking / eStatement |
| Pipeline fingerprint | `240a53bff4190d0e` (unclassified) |

## Summary

**04_edited_online_editor.pdf: review-recommended - 2 finding(s) need attention (2 medium).**

1-page PDF 1.3 produced by iLovePDF; no later edits appended; not digitally signed.

**Key findings**

- [MEDIUM] Processed with a general-purpose PDF editor: tool(s): iLovePDF (online) _(benign if: the recipient compressed, merged or split the file)_
- [MEDIUM] Invisible text on pages without a matching scan image: pages: 1 _(benign if: accessibility or search layer added by a generator)_

**Checked and found in order**

- No page content was changed through appended edits.
- No JavaScript, launch actions, form submission or suspicious attachments.
- File structure is sound: no appended or prepended data, and no repairs needed.

**Recommended next steps**

1. Ask the submitter why the document passed through a general-purpose PDF editor, and request the original file from the issuing system.
2. Compare copied/extracted text with what is visible. Automated systems may read the hidden text.
3. To settle the question, use a stronger source than this analysis, in this order: a valid digital signature from a trusted certificate covering the relevant version; a known-good hash from the issuing system or an immutable archive; the source system's audit log or version history; an independently obtained copy from the issuer.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

### [MEDIUM] Processed with a general-purpose PDF editor

`metadata.editor-tool`, confidence: high, category: metadata

Metadata names a consumer or online PDF editor. Documents issued directly by a bank, insurer or ERP system are not expected to pass through such tools.

- Evidence:
  - **tools**:
    - `iLovePDF (online)`
  - **metadata_fields**:
    - `iLovePDF`
    - `Nordbank Core Banking / eStatement`
    - `Nordbank Core Banking / eStatement`
    - `Nordbank Statement Engine 3.1 (build 2025.11)`

- Possible benign explanations: The recipient compressed, merged or split the file; Editor used to add a signature image

### [MEDIUM] Invisible text on pages without a matching scan image

`content.invisible-text`, confidence: medium, category: content

Text drawn with render mode 3 is not displayed but is picked up by search, copy/paste and automated extraction. It can make a machine read something different from what a person sees.

- Evidence:
  - **pages**:
    - `page=1, invisible_chars=88, text_chars=1276, images=0`

- Possible benign explanations: Accessibility or search layer added by a generator

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
  - **info_producer**: `iLovePDF`
  - **xmp_producer**: `Nordbank Statement Engine 3.1 (build 2025.11)`

## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

