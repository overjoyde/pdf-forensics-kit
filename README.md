# pdf-forensics-kit

Explainable, signature-aware PDF tampering and provenance analysis. It is a rewrite inspired by
[`Rlahuerta/pdf-forensics-toolkit`](https://github.com/Rlahuerta/pdf-forensics-toolkit) (MIT).
See [`docs/ANALYSIS.md`](docs/ANALYSIS.md) for what was kept, the defects found upstream, and what changed,
and [`docs/VALIDATION.md`](docs/VALIDATION.md) for results on 21 public PDFs.

**What it answers**

- Was the document changed after it was created, and *what* changed? It recovers earlier revisions and diffs their text.
- Was it changed **after it was signed**? Is the signature cryptographically intact?
- Does it hide content: invisible text, print-only annotations, layers hidden by default, appended data?
- Does it contain active content (JavaScript, launch/submit actions, attachments, XFA)?
- Which software pipeline produced it, and do documents that claim the same source match?

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

## Use

```bash
# one file -> Markdown on stdout
.venv/bin/pdfforensics analyze invoice.pdf

# a folder -> JSON + Markdown per file, plus a batch summary grouped by production pipeline
.venv/bin/pdfforensics analyze ./case-123 -r --out-dir ./case-123-reports

# CI / scripting: exit 1 if any document is at or above a level
.venv/bin/pdfforensics analyze doc.pdf --json - --fail-on high

# write every revision as a standalone PDF (open rev01 to see the original)
.venv/bin/pdfforensics extract-revisions invoice.pdf --out-dir ./revisions

# compare two documents (identity, metadata, pipeline, page text)
.venv/bin/pdfforensics compare claimed.pdf reference.pdf
```

Inputs are never modified. Reports contain SHA-256, size, UTC timestamp and all library versions (chain of custody).

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
| fingerprint | facts only: producer family, pipeline hash, fonts, filters, xref style |

## Tests

```bash
.venv/bin/python -m pytest
```

All fixtures are generated synthetically at test time (`tests/pdfgen.py`), including a signed
document built with a throw-away self-signed certificate. The repository contains no real documents.

## Handling sensitive documents

The tool runs fully offline and never uploads anything. Reports quote metadata and changed text,
so give them the same classification as the input documents and handle them under the same rules.
