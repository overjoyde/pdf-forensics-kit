# PDF forensic report: 01_original.pdf

**Verdict:** `no-indicators` (level: info)

> No indicators of manipulation were found in the checks performed.

| Field | Value |
|---|---|
| File | `examples/bank-statement/01_original.pdf` |
| Size | 3,441 bytes |
| SHA-256 | `3ea34abe2603483acdd0aa324b110bb8f9c5a4ff1fe739b079743772fd5b4f78` |
| Analysed (UTC) | 2026-09-26T13:56:16.240640+00:00 |
| Tool | pdf-forensics-kit 0.6.0 (pikepdf 10.13.0.post1, qpdf 12.3.2, pypdf 6.19.0, pyHanko 0.37.0, pdfsig 26.08.0) |
| Pages | 1 |
| PDF version | 1.3 (xref: classic, linearized: False) |
| Revisions | 1 (0 incremental update(s)) |
| Signatures | 0 |
| Producer / Creator | Nordbank Statement Engine 3.1 (build 2025.11) / Nordbank Core Banking / eStatement |
| Pipeline fingerprint | `a34d4514761a71c7` (unclassified) |

## Summary

**01_original.pdf: no-indicators - no significant findings.**

1-page PDF 1.3 produced by Nordbank Statement Engine 3.1 (build 2025.11); no later edits appended; not digitally signed.

**Checked and found in order**

- No page content was changed through appended edits.
- No hidden text, print-only annotations or hidden layers.
- No JavaScript, launch actions, form submission or suspicious attachments.
- Metadata dates and producer information are consistent.
- File structure is sound: no appended or prepended data, and no repairs needed.

**Recommended next steps**

1. No action required from the structural analysis. Apply normal business verification (check with the issuer, and compare with known genuine documents) as usual.

**Limitations**

- Structural analysis cannot prove that the content is true; a clean result is not proof of authenticity.

## Findings

_No findings._
## Method

- Verdict rule: Effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity across findings. Incomplete if any analyser failed.
- Structural analysis only. It cannot prove that the content is true or that a document is genuine. A clean result is not proof of authenticity.

