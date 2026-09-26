# Validation on public documents (2026-09-26)

Corpus: 21 public PDFs. None are sensitive, and none are kept in this repository.

- 16 from [py-pdf/sample-files](https://github.com/py-pdf/sample-files): LibreOffice, pdfLaTeX,
  ImageMagick, ReportLab, Google Docs, PDF/A, forms, annotations, attachments, OCGs.
- IRS Form W-9, W3C dummy.pdf, pdf.js `tracemonkey.pdf`.
- Signed samples: iText `hello_signed1.pdf` and Tecxoft `sample01.pdf`.
- Two derived "edited" copies of `hello_signed1.pdf`:
  - an incremental page-content edit made with pyHanko's writer;
  - a full rewrite with pikepdf with the producer set to `iLovePDF`, the way an online editor would do it.

## Result after fixes

| Group | Verdict |
|---|---|
| 16 ordinary files (all generators) | `no-indicators` |
| `hello_signed1.pdf` (signed, untouched) | `no-indicators`, signature intact |
| `sample01.pdf` (legacy `adbe.x509.rsa_sha1` signature) | `minor-anomalies`: signature not validated (pyHanko does not support the format) |
| `irs_fw9.pdf` | `review-recommended`: JavaScript + XFA form (true positives). The UR3 usage-rights signature is classed as info |
| `pdflatex-forms.pdf` | `review-recommended`: SubmitForm action (true positive) + an unreferenced appearance stream |
| `with-attachment.pdf` | `review-recommended`: embedded file (true positive) |
| `edited_incremental.pdf` | `strong-indicators`: content changed after signing, and pyHanko reports illegal modification |
| `edited_rewrite.pdf` | `strong-indicators`: broken signature + editor tool in metadata |

One file (`unreadablemetadata.pdf`) is deliberately broken. qpdf refuses it, and it is reported as `not-analysed` rather than as clean.

## Defects found and fixed during validation

1. **Direct (nested) objects were not scanned.** A JavaScript action written as a direct `/A` dictionary inside an
   annotation, or a file specification written inline in the `/EmbeddedFiles` name tree, was missed (false
   negative on `with-attachment.pdf` and `pdflatex-forms.pdf`). The active-content scan now descends into direct
   children of every object.
2. **Unreferenced objects were too noisy:** 8 of 21 benign files were flagged `low`. Indirect numbers (`/Length`),
   empty dictionaries, fonts and resources are now `info`. Only unreferenced pages, annotations or
   text-drawing streams raise the finding to `low`.
3. **UR3 usage-rights signatures** (Adobe Reader extensions, e.g. IRS forms) were treated as document signatures,
   and the `/EF` permissions array in their TransformParams was misread as an embedded file. They are now
   classified separately as info.
4. **Signatures pyHanko skips** (legacy sub-filters) produced no finding. They now yield `signature.not-validated`.

Each fix has a regression test in `tests/test_analysis.py`.

## Office documents (v0.3.0, 2026-09-26)

Corpus: 11 public Office files. 10 are from the [Apache POI test data](https://github.com/apache/poi/tree/trunk/test-data)
(Word 2007/LibreOffice DOCX, macro-enabled DOCM/XLSM, XLSX with tables and data, a PPTX). The eleventh is
Apple Numbers' bundled `FontTemplate.xlsx`.

| File | Verdict | Findings |
|---|---|---|
| 7 ordinary DOCX/XLSX/PPTX files | `no-indicators` | Info only (comments, hyperlinks). One PPTX has `zero-edit-time` (low confidence, so it does not raise the verdict) |
| `SimpleMacro.docm`, `SimpleMacro.xlsm` | `significant-indicators` | `office.macros` (true positive, correct extension, so no renaming flag) |
| `delins.docx` | `review-recommended` | `office.tracked-changes`: 36 pending changes, with the deleted text recovered (true positive) |

Synthetic cases in `tests/test_office.py` cover what public samples rarely contain: deleted invoice amounts in
tracked changes, hidden text, DDE fields, remote-template injection, macros in a `.docx`, very-hidden sheets,
hidden slides, duplicate and path-traversal parts, XML entity expansion (refused), and extension mismatches.

Poppler `pdfsig` 26.08 was checked against pyHanko on intact, post-signing-edited and byte-altered signed PDFs.
Both validators agree in every case: intact, "not total document signed" plus an intact signed range, and
digest mismatch.
