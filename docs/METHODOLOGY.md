# Methodology

## Evidence handling

1. **Capture once.** The file is opened without following symbolic links and read through a single
   descriptor, then hashed (SHA-256). The file is rejected if its size or modification time changes while
   it is read. Every analyser works on these captured bytes, never on the path again.
2. **External tools get a copy.** Optional validators (Poppler `pdfsig`) receive a private, read-only
   temporary copy of the captured bytes. The copy is deleted afterwards.
3. **Path check afterwards.** If the file at the given path no longer matches the captured size and
   mtime when the analysis ends, the report says so (`input.changed-after-capture`).
4. **No network, no execution.** Nothing is uploaded. Macros, JavaScript, DDE fields, embedded files
   and external links are never executed or fetched. `pdfsig` runs with `-no-ocsp` unless
   `--online-revocation` is given explicitly.
5. **Report provenance.** Every report records the SHA-256, size, UTC time and the versions of every
   library and external tool used. Report files are named `<file>.<sha256 prefix>.*`, so same-named files
   from different folders never overwrite each other.

## Findings, not scores

Each finding has a **severity** (impact if the concern is real) and a **confidence** (how directly the
evidence shows it). These are independent. A macro is high-severity and high-confidence as a *security*
fact, and says nothing about *who* changed the content. The verdict is the highest effective severity:
the severity, lowered one step when confidence is low. The rule is printed in every report. There is no
authenticity probability, because none could be calibrated honestly.

Findings state benign explanations wherever common legitimate workflows produce the same artefact
(signatures and form filling create incremental updates, OCR creates invisible text, review workflows
leave tracked changes).

## What is normal (do not over-interpret)

- Different creation and modification dates.
- Incremental PDF updates from signing, form filling or LTV enrichment.
- Author and last editor being different people.
- Missing metadata (it is not evidence of deletion).
- Unused fonts and resources left behind by generators.
- A present signature (it is not necessarily valid, trusted or covering the current version).
- A structurally clean file (its visible content can still be false).

## Stronger verification sources

Structural analysis is the weakest of the usual sources of evidence. In descending order of evidential
value:

1. A valid digital signature from a trusted certificate, covering the relevant revision, with revocation checked.
2. A known-good hash from the issuing system or an immutable archive.
3. The source system's audit log or version history, tied to authenticated identities.
4. An independently obtained copy from the issuer.
5. Internal metadata and structure of the questioned document (what this tool analyses).

Summaries recommend moving up this list whenever a document needs attention.

## Scope

The tool does not judge whether statements in a document are true. It does not replace chain-of-custody
procedures, expert examination, or cryptographic validation against an approved trust list.
