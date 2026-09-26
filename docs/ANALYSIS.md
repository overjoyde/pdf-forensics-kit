# Analysis of upstream `Rlahuerta/pdf-forensics-toolkit`

Reviewed commit `9d300b4751761a3b99e48643e2ae4314dc146072` (2026-04-27), MIT licence.
Scope: read-only source review. No upstream code was executed except a couple of
one-line reproductions against synthetic PDFs, noted below.

## 1. What is worth keeping

| Idea | Why it is good | Kept in this project as |
|------|----------------|-------------------------|
| Recovering earlier revisions of incrementally-updated PDFs and diffing their text | This is the strongest real forensic signal: an old invoice amount can still sit in the file | `revisions` analyser + `extract-revisions` command |
| Source fingerprinting (producer, PDF version, filters, fonts) and grouping documents by pipeline | Useful for "did these documents come from the same system?" | `fingerprint` module + `group` in the batch report |
| Active-content scan (JavaScript, Launch, embedded files, URIs) | Standard malicious-PDF triage | `active_content` analyser (made much broader) |
| Hidden annotations, optional content, invisible text as tampering vectors | Correct threat model (shadow attacks) | `content` analyser (made more precise) |
| Info dict vs XMP metadata cross-check | Genuine inconsistency signal | `metadata` analyser (with real date parsing) |
| pyHanko for signature validation | Correct library choice | optional `signatures` analyser |
| File size limit and `%PDF-` header check | Basic input hygiene | `document.load()` |

## 2. Defects found (false positives and false negatives)

Severity is my assessment of impact on a report a fraud investigator would rely on.

| # | Upstream behaviour | Problem | Impact |
|---|-------------------|---------|--------|
| D1 | Counts `%%EOF` occurrences in the raw bytes to detect incremental updates | **Linearized ("fast web view") PDFs always contain 2 `%%EOF`** - reproduced with a qpdf-linearized blank page. Also matches `%%EOF` inside streams/embedded files. | High: normal web-optimised PDFs are reported as "modified" |
| D2 | Scans with `re.findall(rb'xref\s')` and compares with `startxref` count | The regex also matches the `xref` inside `startxref`. **Every clean classic-xref PDF gets "XREF/startxref mismatch" +10 risk** - reproduced (2 vs 1 on a blank page). | High: systematic false positive |
| D3 | `/ID[0] != /ID[1]` => "Document ID changed after creation", +20 | Many producers write two different IDs at creation time. | High false positive rate |
| D4 | CreationDate != ModDate => "modified" | Normal for almost every document (seconds apart, save-on-export). | High false positive rate |
| D5 | "Modification before creation" only compares **year** | Misses the actual impossible cases (same year, earlier month/day). | False negative |
| D6 | XMP vs Info date compared on first 10 chars, no timezone | Flags documents created close to midnight in non-UTC zones. | False positive |
| D7 | Creator/Producer "from different systems" when the first 5 letters differ | `Microsoft Word` + `Microsoft: Print To PDF` is fine, `Writer` + `LibreOffice` is flagged. Noise. | False positive |
| D8 | Two different `SUSPICIOUS_PRODUCERS` lists; the one actually used includes `chrome`, `firefox`, `microsoft print to pdf` | Contradicts `constants.py` which marks them benign. Browser-printed documents get +15 risk. | False positive |
| D9 | Substring search `b'3 Tr'` in page content | Also matches `13 Tr`, `23 Tr` ... Misses text inside Form XObjects. **Every OCR'd scan uses invisible text (Tr 3)** and is flagged as a *shadow attack* (+25). | High false positive; also false negatives |
| D10 | Hybrid xref files (classic + stream) flagged as anomaly | Hybrid-reference is a spec-defined compatibility format. | False positive |
| D11 | Entropy "suspicious" if > 50 % of streams have entropy > 7.5 | `read_bytes()` does not decode DCT (JPEG) images, so photo/scan PDFs are always "high entropy". | False positive |
| D12 | Objects enumerated with `get_object((n, 0))` for `n < 1000/2000` | Ignores generation > 0 objects, silently truncates large files, and asking for a non-existent object may return a null object that is then counted as an orphan. | False positives and silent false negatives |
| D13 | Orphan detection runs on the **resolved** (latest) object table | Objects superseded by an incremental update are not visible there, so the most important remnants are never found. | False negative |
| D14 | Every incremental update adds risk | **Each digital signature is, by design, an incremental update.** Signed PDFs look tampered. No correlation between updates and signature ByteRanges. | High false positive for exactly the documents that are most trustworthy |
| D15 | No check whether bytes were added **after** the last signature | That is the key signed-document tampering case. pyHanko's modification analysis is not surfaced. | False negative |
| D16 | Active-content scan only on catalog-level `/OpenAction`/`/AA` and gen-0 objects | Misses page/annotation `/AA`, JavaScript name tree, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE`, `/RichMedia`, XFA. | False negative |
| D17 | Optional content: flags the mere presence of layers | The risk is a layer that is **OFF by default** (different on screen vs print), not layers in general. | Both |
| D18 | `except Exception: pass` / `logger.warning` everywhere | A failed check silently counts as "clean". Absence of evidence becomes a 100/100 integrity score. | Critical for a forensic tool |

## 3. Design / methodology issues

1. **Unexplained magic-number scores presented as "Integrity 0-100".** Points are summed across
   overlapping checks (incremental updates are counted in the modification score, the tampering
   score *and* the integrity score). A legal reader cannot trace why a document got 55.
   *Improvement:* emit a list of **findings** (id, severity, confidence, evidence, benign explanations).
   Derive an overall assessment from the findings by a documented rule, and show the rule.
2. **No chain-of-custody data.** The report has no SHA-256 of the input, tool version, library versions
   or UTC timestamp. *Improvement:* every report carries them.
3. **No machine-readable output.** Markdown only. *Improvement:* JSON is the primary output, Markdown is rendered from it.
4. **Each file is parsed ~10 times by 3 libraries** (PyMuPDF, pikepdf, pypdf). *Improvement:* read bytes once, open pikepdf once. Use pypdf only for per-revision text extraction.
5. **Licensing:** the project is labelled MIT but depends on **PyMuPDF (AGPL-3.0)**. *Improvement:* dropped PyMuPDF. The new project uses pikepdf (MPL-2.0), pypdf (BSD), pyHanko (MIT, optional).
6. **Dependency surface:** 13 runtime deps, including small single-maintainer packages (`peepdf-3`, `pdfid`, `endesive`). *Improvement:* 2 required deps + 1 optional.
7. **Structure:** a 1 490-line top-level script duplicated by the package, and emoji-heavy output. *Improvement:* one package, small analysers with a common interface, plain-text reports.
8. **Tested only on Ubuntu.** *Improvement:* the test suite builds all fixtures synthetically at test time and runs anywhere pikepdf runs.

## 4. Improvements implemented here

- Revision boundaries come from the **`startxref` -> `/Prev` chain** (classic and xref-stream trailers), with linearization detected and discounted. This fixes D1/D2/D10.
- **Per-revision object diff:** which objects were added, changed or removed in each update. Old versions of superseded objects are recoverable (fixes D13).
- **Per-revision text diff** (kept from upstream, now on correct boundaries) and `extract-revisions` to write each revision as a standalone PDF for the examiner.
- **Signature-aware**: signature ByteRanges are mapped to revisions. Updates that only add a signature are classed as benign. Bytes appended after the last signature are a high-severity finding (fixes D14/D15). pyHanko validation runs when installed.
- **Content streams are tokenised** with `pikepdf.parse_content_stream` (fixes D9), including Form XObjects. Invisible text on a page that also has a full-page image is labelled *likely OCR*.
- Optional content is only flagged when groups are **OFF by default** or differ between view and print (D17).
- **Real PDF/XMP date parsing** with timezone offsets. Checks: modification before creation, dates in the future, Info vs XMP disagreement beyond a tolerance. Also extracts the XMP edit history (`xmpMM:History`) when present (D4-D6).
- **Complete active-content scan** over all objects, including actions in annotations, pages and name trees (D16).
- **Structural checks:** data before the header, trailing data after the final `%%EOF`, qpdf repair warnings, unreachable objects in the final table (computed correctly), encryption.
- **Failed checks are reported as findings** (`analysis-error`) and lower the confidence of the verdict instead of being hidden (D18).
- **Chain of custody:** SHA-256, size, tool/library versions and UTC timestamp in every report.
- **Batch mode:** groups documents by source fingerprint.

## 5. Out of scope / possible next steps

- Image-level forensics (error-level analysis, JPEG quantisation tables, copy-move detection).
- Font-level forensics (glyphs from subset fonts that do not match the rest of the document, which shows edited amounts).
- Visual rendering diff between revisions (needs a renderer; Poppler/`pdftoppm` via Brew would avoid AGPL).
- Trust-list validation of signatures against EU LOTL/AATL.
