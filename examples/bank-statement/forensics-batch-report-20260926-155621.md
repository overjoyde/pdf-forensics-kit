# Document forensic batch summary

## Executive summary

**7 document(s) submitted: 4 need attention, 2 without significant findings, 1 could not be analysed.**

Verdicts: `no-indicators` x2, `review-recommended` x2, `significant-indicators` x1, `strong-indicators` x1

**Needs attention (most severe first)**

- 05_signed_then_edited.pdf: `strong-indicators` - Revision 3 changes page content after the document was signed
- 03_edited_in_acrobat.pdf: `significant-indicators` - Revision 2 changes page content
- 04_edited_online_editor.pdf: `review-recommended` - Processed with a general-purpose PDF editor
- 06_transactions_export.xlsx: `review-recommended` - Very-hidden worksheets

**Not analysed**

- PATH: file not found: PATH

The documents come from 5 distinct production pipeline(s). Documents that claim the same issuer but fall into different pipelines deserve a closer look.

## Documents

| File | Format | Verdict | Revisions / tracked changes | Signatures | Top findings | Pipeline |
|---|---|---|---|---|---|---|
| 01_original.pdf | PDF | `no-indicators` | 1 | 0 | - | `a34d4514761a71c7` |
| 02_original_signed.pdf | PDF | `no-indicators` | 2 | 1 | - | `c6a10d6fe84b6c96` |
| 03_edited_in_acrobat.pdf | PDF | `significant-indicators` | 2 | 0 | revisions.content-changed | `c7235897064a6eac` |
| 04_edited_online_editor.pdf | PDF | `review-recommended` | 1 | 0 | metadata.editor-tool, content.invisible-text | `240a53bff4190d0e` |
| 05_signed_then_edited.pdf | PDF | `strong-indicators` | 3 | 1 | revisions.content-changed, signature.disallowed-modification, signature.bytes-after-last-signature | `c7235897064a6eac` |
| 06_transactions_export.xlsx | XLSX | `review-recommended` | 0 tracked | 0 | office.very-hidden-sheets | `355dfa5b5a7b1a16` |
| PATH | - | `not-analysed` | - | - | file not found: PATH | - |

## Documents grouped by production pipeline

- `c7235897064a6eac` (Adobe Acrobat): 03_edited_in_acrobat.pdf, 05_signed_then_edited.pdf
- `a34d4514761a71c7` (unclassified): 01_original.pdf
- `c6a10d6fe84b6c96` (unclassified): 02_original_signed.pdf
- `240a53bff4190d0e` (unclassified): 04_edited_online_editor.pdf
- `355dfa5b5a7b1a16` (Microsoft Excel): 06_transactions_export.xlsx

