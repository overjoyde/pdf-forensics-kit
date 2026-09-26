---
name: document-forensics
description: Analyse local PDF and Office (DOCX/XLSX/PPTX) documents for tampering, provenance and hidden or active content with the pdf-forensics-kit CLI (`pdfforensics`). Use when asked whether a document may have been altered, to compare two copies, to recover earlier PDF revisions, or to summarise forensic findings. Never use it to declare a document authentic.
---

# Document forensics with pdf-forensics-kit

## Rules

1. **Preserve the evidence.** Never edit, re-save, "repair", print-to-PDF or open the questioned file in an
   editor. Do not enable macros, run JavaScript or follow its links.
2. **Stay local.** Do not upload the file or send its contents to web services. Reports quote metadata and
   changed text, so they carry the same classification as the document. Keep them local too.
3. **Confidential material:** summarise findings by id and severity instead of pasting quoted document
   text into chat. Strictly confidential material must not be processed with AI tooling at all.
4. **Never turn `no-indicators` into "authentic" or "not tampered".** It means that the implemented checks
   found nothing.

## Workflow

1. Check that the CLI is available: `pdfforensics --version`. If it is missing, stop and ask the user to
   install the kit (`pip install -e '.[signatures]'` in its repository). Do not substitute an online service.
2. Analyse and write reports next to the case, not next to the evidence:

   ```bash
   pdfforensics analyze "/abs/path/file-or-folder" -r --out-dir "/abs/path/case-reports"
   ```

   Add `--no-external-tools` to skip Poppler `pdfsig`. Never add `--online-revocation` unless the user
   explicitly allows network access.
3. Read `<file>.<hash>.summary.md` first, then the JSON (`*.forensics.json`) for evidence.
4. For PDFs with `revisions.content-changed`, recover the earlier versions:
   `pdfforensics extract-revisions file.pdf --out-dir case-reports/revisions`.
5. To compare a questioned copy with a reference copy: `pdfforensics compare reference.pdf questioned.pdf`.
6. Regenerate summaries later with `pdfforensics summarize case-reports/*.forensics.json`.

## Reporting back

Lead with the verdict label and the SHA-256. Then give the key findings with their decisive evidence and
the most likely benign explanation, and the recommended next steps. State the limitations: analysis
incomplete, signatures not validated, external tool unavailable. For a consequential conclusion,
recommend a stronger source (see [references/interpretation.md](references/interpretation.md)).
