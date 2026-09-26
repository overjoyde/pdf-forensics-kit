# Example case: a tampered bank statement

**Every file here is fictitious.** "Nordbank Demo AB", the customer Erik Exempel, the account number
and the IBAN are invented; the IBAN has check digits `00`, so it can never be valid. Every page is watermarked
`SPECIMEN` and says in the footer that it is a test document. Regenerate the files with:

```bash
python examples/make_bank_statements.py            # writes examples/bank-statement/
```

## The story

Erik Exempel applies for a loan and hands in his January 2026 statement. He has raised his salary from
**32 450,00** to **52 450,00 SEK** and corrected every running balance after it, so the statement still adds
up (closing balance 29 954,52 → 49 954,52). On screen, the forged statement looks as authentic as the
original.

| File | What happened | Expected verdict |
|---|---|---|
| `01_original.pdf` | Issued by the bank's statement engine | `no-indicators` |
| `02_original_signed.pdf` | Same, digitally signed by the bank (self-signed test certificate) | `no-indicators` |
| `03_edited_in_acrobat.pdf` | Amounts edited in a desktop PDF editor and saved normally (incremental save). The Info producer and ModDate were updated, the XMP metadata was not | `significant-indicators` |
| `04_edited_online_editor.pdf` | Edited with an online editor that rewrites the whole file. The old amounts are left underneath as invisible text | `review-recommended` |
| `05_signed_then_edited.pdf` | The signed statement, edited afterwards | `strong-indicators` |
| `06_transactions_export.xlsx` | The bank's Excel export, salary changed in the visible sheet. The untouched export is still inside, in a *very hidden* sheet | `review-recommended` |

## Try it

```bash
pdfforensics analyze examples/bank-statement --summary
pdfforensics extract-revisions examples/bank-statement/03_edited_in_acrobat.pdf --out-dir /tmp/revs
pdfforensics compare examples/bank-statement/01_original.pdf examples/bank-statement/04_edited_online_editor.pdf
```

## What the tool finds

**03 (desktop editor):** the original is still inside the file.

> - [HIGH] Revision 2 changes page content: removed: "2026-01-25 Lön Exempelföretaget AB 32 450,00 36 602,52" … added: "2026-01-25 Lön Exempelföretaget AB 52 450,00 56 602,52" …

It also flags the Info/XMP date and producer disagreement: the editor updated one metadata store and not the other.

**04 (online editor):** there is no revision history left, but:
- `metadata.editor-tool`: iLovePDF is in the tool chain of a statement that should come straight from a bank;
- `content.invisible-text`: the original amounts are still on the page as invisible text;
- the XMP metadata still names the bank's engine.

**05 (signed, then edited):** the strongest case.

> - [CRITICAL] Revision 3 changes page content after the document was signed
> - [HIGH] Changes after signature 'NordbankSeal' go beyond what the signer allowed (pyHanko: ILLEGAL_MODIFICATIONS)

`extract-revisions` gives you the signed version (revision 2), which is authoritative.

**06 (Excel export):** `office.very-hidden-sheets` reports the sheet `_export_orig`, which cannot be unhidden
from the Excel interface. It holds the original salary. The properties also show the file was last saved by
"Erik Exempel", not by the bank's export.

**01 and 02** are controls. Signing adds an incremental update and appends pyHanko to the producer, and
neither is reported as tampering.

## What this example also shows

The tool analyses *structure*. If the forger had re-typed the statement from scratch in a word processor and
exported a fresh PDF, no revision history or leftovers would remain. You would then rely on the production
fingerprint (the "bank" statement produced by Microsoft Word) and on the stronger sources in the main README:
a bank signature, a copy fetched directly from the bank, or the bank's own records.
