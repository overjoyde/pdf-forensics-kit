# Document forensic report: 06_transactions_export.xlsx

**Verdict:** `review-recommended` (level: medium)

> Anomalies that need an explanation before relying on the document.

| Field | Value |
|---|---|
| File | `examples/bank-statement/06_transactions_export.xlsx` |
| Size | 4,140 bytes |
| SHA-256 | `8972e1e45a46c086cccb400b939cbe6b07692268c03f0599bcfdcbf008bca458` |
| Analysed (UTC) | 2026-09-26T13:56:16.597902+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Format | XLSX |
| Application | Microsoft Excel 16.0300 |
| Author / last saved by | Nordbank eStatement Export / Erik Exempel |
| Created / modified | 2026-02-01T05:12:40Z / 2026-09-18T19:51:12Z |
| Pipeline fingerprint | `355dfa5b5a7b1a16` |

## Summary

**06_transactions_export.xlsx: review-recommended - 1 finding(s) need attention (1 medium).**

XLSX document produced by Microsoft Excel 16.0300; author 'Nordbank eStatement Export', last saved by 'Erik Exempel'; created 2026-02-01T05:12:40Z, modified 2026-09-18T19:51:12Z; no pending tracked changes; no macros.

**Key findings**

- [MEDIUM] Very-hidden worksheets: sheets: _export_orig _(benign if: lookup tables in spreadsheet tools and templates)_

**Checked and found in order**

- No pending tracked changes (no deleted text left in the file).
- No macros, DDE fields, remote templates, external content or embedded objects.
- Document properties (dates, editing time) are consistent.
- Package structure is sound: consistent manifest, no duplicate or disguised parts.

**Recommended next steps**

1. Inspect the very-hidden sheets (VBA editor or a ZIP viewer) and check whether visible figures depend on them.
2. To settle the question, use a stronger source than this analysis, in this order: a valid digital signature from a trusted certificate covering the relevant version; a known-good hash from the issuing system or an immutable archive; the source system's audit log or version history; an independently obtained copy from the issuer.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

### [MEDIUM] Very-hidden worksheets

`office.very-hidden-sheets`, confidence: high, category: content

'veryHidden' sheets cannot be unhidden from the Excel user interface, only through VBA or by editing the file. Visible figures can depend on them without the reader knowing.

- Evidence:
  - **sheets**:
    - `_export_orig`

- Possible benign explanations: Lookup tables in spreadsheet tools and templates

### [info] Last edited by a different person than the author

`office.different-editor`, confidence: high, category: metadata

The author and last-modified-by fields name different users. This is normal in shared workflows, but worth knowing when a single person is supposed to have produced the document.

- Evidence:
  - **creator**: `Nordbank eStatement Export`
  - **last_modified_by**: `Erik Exempel`

## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

