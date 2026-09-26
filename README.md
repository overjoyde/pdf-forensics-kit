# pdf-forensics-kit

Explainable, signature-aware tampering and provenance analysis for **PDF and Office documents
(DOCX / XLSX / PPTX)**. It is a rewrite inspired by
[`Rlahuerta/pdf-forensics-toolkit`](https://github.com/Rlahuerta/pdf-forensics-toolkit) (MIT).

- [`docs/ANALYSIS.md`](docs/ANALYSIS.md): what was kept, the defects found upstream, and what changed.
- [`docs/VALIDATION.md`](docs/VALIDATION.md): results on public PDF and Office samples.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md): evidence handling, the findings model, and stronger verification sources.

**What it answers**

- Was the document changed after it was created, and *what* changed? It recovers earlier revisions and diffs their text.
- Was it changed **after it was signed**? Is the signature cryptographically intact?
- Does it hide content: invisible text, print-only annotations, layers hidden by default, appended data?
- Does it contain active content (JavaScript, launch/submit actions, attachments, XFA)?
- Which software pipeline produced it, and do documents that claim the same source match?
- For Word/Excel/PowerPoint: are there pending tracked changes, with the **deleted text still in the file**? Is
  there hidden text, are there hidden or very-hidden sheets or hidden slides? Does it contain macros, DDE fields,
  remote templates, external content or embedded objects? Is the package disguised or malformed?

Every result is a **finding** with severity, confidence, evidence and possible benign explanations.
The verdict rule is printed in every report. There are no hidden point totals.

> Structural analysis only. It cannot prove that content is true, and a clean result is not proof of authenticity.

## Install (local, isolated)

```bash
git clone https://github.com/overjoyde/pdf-forensics-kit.git
cd pdf-forensics-kit
python3 -m venv .venv
.venv/bin/pip install -e '.[signatures,dev]'   # drop 'signatures' to skip pyHanko
```

Runtime dependencies: `pikepdf` (MPL-2.0), `pypdf` (BSD), and optionally `pyhanko` (MIT). There is no AGPL code and nothing phones home.
Office analysis uses only the Python standard library.

**Optional second signature validator:** if Poppler's `pdfsig` is installed (`brew install poppler`, or
`apt install poppler-utils`), signed PDFs are also checked by it. Signature integrity, certificate trust and
revocation are reported separately, and the result is cross-checked against pyHanko. `pdfsig` runs offline
(`-no-ocsp`) unless you pass `--online-revocation`. Disable it with `--no-external-tools`.

## Use

```bash
# one file -> Markdown on stdout
.venv/bin/pdfforensics analyze invoice.pdf

# a folder of PDFs / DOCX / XLSX / PPTX -> JSON + Markdown + summary per file, plus a batch summary
.venv/bin/pdfforensics analyze ./case-123 -r --out-dir ./case-123-reports

# plain-language summary when the analysis is done (stdout, or a file)
.venv/bin/pdfforensics analyze ./case-123 --summary
.venv/bin/pdfforensics analyze invoice.pdf --summary invoice.summary.md

# regenerate summaries later from saved JSON reports
.venv/bin/pdfforensics summarize ./case-123-reports/*.forensics.json -o case-123-summary.md

# CI / scripting: exit 1 if any document is at or above a level
.venv/bin/pdfforensics analyze doc.pdf --json - --fail-on high

# write every revision as a standalone PDF (open rev01 to see the original)
.venv/bin/pdfforensics extract-revisions invoice.pdf --out-dir ./revisions

# compare two documents (identity, metadata, pipeline, page text)
.venv/bin/pdfforensics compare claimed.pdf reference.pdf
```

Inputs are never modified. The file is captured once without following symlinks, hashed, and analysed
from those bytes; a file that changes while it is read is rejected. Reports contain SHA-256, size, UTC
timestamp and all library/tool versions, and are named `<file>.<sha256-prefix>.forensics.{json,md}` and
`.summary.md`, so same-named files never overwrite each other.

### Summary

Every analysis ends with a generated **summary** (the `summary` key in JSON, the `## Summary` section in Markdown,
and `<name>.summary.md` with `--out-dir`). It is written for non-technical readers:

- **Headline:** verdict and how many findings need attention, by severity.
- **Document profile:** pages, producing software, appended edits, signature status.
- **Key findings:** each with its decisive evidence (e.g. `removed: "Total: 100 SEK"; added: "Total: 9 SEK"`) and the most likely benign explanation.
- **Checked and found in order:** what the checks ruled out.
- **Recommended next steps** for the findings present.
- **Limitations:** incomplete analysis, unverifiable signatures, scan limits, and the general disclaimer.

For several files, an executive summary lists the documents needing attention, most severe first.
The summary is a pure function of the report, so `pdfforensics summarize` reproduces it exactly from saved JSON.

## Verdict levels

| Level | Label | Meaning |
|---|---|---|
| info | `no-indicators` | Nothing found in the checks performed |
| low | `minor-anomalies` | Usually benign; review if the document matters |
| medium | `review-recommended` | Needs an explanation before relying on the document |
| high | `significant-indicators` | Post-creation modification or hidden content |
| critical | `strong-indicators` | e.g. content changed after signing, broken signature |

Rule: effective severity = severity, one step lower when confidence is low. Verdict = highest effective severity. A failed analyser marks the report **incomplete**. It never counts as clean.

## Checks

| Analyser | Findings (ids) |
|---|---|
| structure | `data-before-header`, `data-after-eof`, `extra-eof-markers`, `repaired`, `unreachable-objects`, `encrypted`, `xref-chain-broken` |
| revisions | `content-changed` (with text diff), `annotation-or-form-update`, `metadata-update`, `signature-update`, `other-update` |
| signatures | `intact`, `broken`, `disallowed-modification`, `bytes-after-last-signature`, `malformed-byterange`, `validation-error` |
| metadata | `modified-before-created`, `future-date`, `info-xmp-date-mismatch`, `producer-mismatch`, `editor-tool`, `manipulation-library`, `xmp-history`, `absent` |
| content | `invisible-text`, `ocr-text-layer`, `print-only-annotations`, `hidden-annotations`, `layer-view-print-differs`, `layers-hidden-by-default` |
| active_content | `javascript`, `launch-action`, `submit-or-import`, `remote-goto`, `multimedia`, `xfa`, `embedded-files`, `e-invoice-attachment`, `additional-actions`, `uris` |
| pdfsig (optional) | `integrity-ok`, `integrity-failure`, `certificate-revoked`, `certificate-expired`; `signature.validators-disagree` |
| fingerprint | facts only: producer family, pipeline hash, fonts, filters, xref style |
| input (all formats) | `extension-mismatch`, `changed-after-capture` |
| office container | `not-an-office-package`, `extension-mismatch`, `duplicate-parts`, `unsafe-paths`, `encrypted-parts`, `compression-bomb`, `resource-limit`, `opc-nonconformant`, `parts-not-parsed`, `legacy-format` |
| office metadata | `modified-before-created`, `printed-before-created`, `future-date`, `different-editor`, `zero-edit-time`, `remote-template-name`, `metadata-absent` |
| office content | `tracked-changes` (with deleted/inserted text and authors), `track-changes-enabled`, `hidden-text`, `very-hidden-sheets`, `hidden-sheets`, `external-workbook-links`, `hidden-slides`, `comments` |
| office active content | `macros` (flags macros in macro-free extensions), `remote-template`, `dde-field`, `external-content`, `embedded-objects`, `activex`, `hyperlinks`, `xml-signature` (detected, not validated) |

## Tests

```bash
.venv/bin/python -m pytest
```

All fixtures are generated synthetically at test time (`tests/pdfgen.py`, `tests/officegen.py`),
including a signed document built with a throw-away self-signed certificate. The repository contains no
real documents. The `pdfsig` integration tests run only when Poppler is installed.

## Agent skill

`.agents/skills/document-forensics/` contains a skill for coding agents (Codex, opencode and similar).
It covers how to run the CLI safely, and how to report results without over-interpreting them: a
`no-indicators` result is never "authentic".

## Handling sensitive documents

The tool runs fully offline and never uploads anything. Reports quote metadata and changed text,
so give them the same classification as the input documents and handle them under the same rules.
