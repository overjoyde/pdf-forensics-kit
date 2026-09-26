# Interpreting pdf-forensics-kit results

## Verdict labels

| Label | Say | Do not say |
|---|---|---|
| `no-indicators` | "The checks performed found no indicators of manipulation." | "The document is authentic / genuine / untampered." |
| `minor-anomalies` | "Minor anomalies that usually have benign causes." | "Suspicious." |
| `review-recommended` | "Anomalies that need an explanation before relying on the document." | "Forged." |
| `significant-indicators` | "Significant structural indicators of modification or hidden content." | "Proven fraud." |
| `strong-indicators` | "Strong indicators, for example content changed after signing or a broken signature." | "Proven fraud" (intent and author are still unknown). |

An **incomplete** verdict means a check failed or the format is only partly supported. Say which checks
are missing.

## Commonly benign

- CreationDate differs from ModDate.
- Incremental updates that only add a signature, form values or DSS/LTV data.
- OCR text layers (invisible text over a scanned image).
- Author differs from last editor.
- Tracked changes in documents under review.
- Hidden helper sheets in spreadsheet templates.
- Unused fonts or resources.

## Weight of evidence (strongest first)

1. A valid signature from a trusted certificate covering the relevant revision (revocation checked).
2. A known-good hash from the issuing system or an immutable archive.
3. The source system's audit log or version history.
4. An independent copy obtained from the issuer.
5. This tool's structural findings.

Structural findings justify asking for 1–4. They rarely settle a question on their own.

## High-signal findings

- `revisions.content-changed` with text evidence: an earlier version is recoverable (`extract-revisions`).
- Content changed **after signing**, `signature.broken`, `pdfsig.integrity-failure`: the signed version differs from what is shown.
- `office.tracked-changes` with `deleted_text`: the original wording or amount is still inside the file.
- `metadata.editor-tool` on a document that supposedly came straight from an issuing system.
- `signature.validators-disagree`: needs manual expert review.
