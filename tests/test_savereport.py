import builtins

import officegen as og
import pdfgen
from pdfforensics.cli import main
from pdfforensics.repl import ForensicsShell
from pdfforensics.savereport import SUFFIX, ask_yes_no, report_path_for, save_reports


def _tampered() -> bytes:
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    return pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK"))})


def _answers(monkeypatch, *answers):
    it = iter(answers)
    asked = []

    def fake_input(prompt=""):
        asked.append(prompt)
        return next(it)

    monkeypatch.setattr(builtins, "input", fake_input)
    return asked


def test_yes_saves_markdown_next_to_the_document(tmp_path, monkeypatch, capsys):
    case = tmp_path / "Case 42"
    case.mkdir()
    doc = case / "invoice.pdf"
    doc.write_bytes(_tampered())
    before = doc.read_bytes()
    sh = ForensicsShell(colour=False)
    sh.interactive = True
    asked = _answers(monkeypatch, "y")
    sh.onecmd(f'"{doc}"')
    report = case / ("invoice.pdf" + SUFFIX)
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    assert text.startswith("# PDF forensic report: invoice.pdf") and "Total: 900 SEK" in text
    assert "## Summary" in text and "## Findings" in text
    assert doc.read_bytes() == before                       # the evidence is untouched
    assert "[y/N]" in asked[0] and str(case) in asked[0]
    assert "report saved:" in capsys.readouterr().out


def test_no_saves_nothing(tmp_path, monkeypatch, capsys):
    doc = tmp_path / "offer.docx"
    doc.write_bytes(og.build("docx"))
    sh = ForensicsShell(colour=False)
    sh.interactive = True
    _answers(monkeypatch, "n")
    sh.onecmd(f'"{doc}"')
    assert list(tmp_path.glob("*" + SUFFIX)) == []
    assert "not saved" in capsys.readouterr().out
    sh.onecmd("save")                                        # ...but can still be saved afterwards
    assert (tmp_path / ("offer.docx" + SUFFIX)).exists()


def test_enter_means_no_and_bad_answers_are_asked_again(monkeypatch, capsys):
    _answers(monkeypatch, "maybe", "")
    assert ask_yes_no("Save?") is False
    assert "Please answer y" in capsys.readouterr().out
    _answers(monkeypatch, "ja")
    assert ask_yes_no("Save?") is True


def test_existing_report_is_never_overwritten(tmp_path):
    doc = tmp_path / "a.pdf"
    doc.write_bytes(b"%PDF-1.4")
    first = report_path_for(doc)
    first.write_text("old")
    second = report_path_for(doc)
    assert second != first and second.name.startswith("a.pdf.forensics-report-") and second.suffix == ".md"
    assert first.read_text() == "old"


def test_folder_analysis_saves_each_report_in_its_own_folder_plus_batch(tmp_path, monkeypatch):
    (tmp_path / "jan").mkdir()
    (tmp_path / "feb").mkdir()
    (tmp_path / "jan" / "s1.pdf").write_bytes(pdfgen.build())
    (tmp_path / "feb" / "s2.pdf").write_bytes(_tampered())
    sh = ForensicsShell(colour=False)
    sh.interactive = True
    _answers(monkeypatch, "yes")
    sh.onecmd(f'analyze "{tmp_path}"')
    assert (tmp_path / "jan" / ("s1.pdf" + SUFFIX)).exists()
    assert (tmp_path / "feb" / ("s2.pdf" + SUFFIX)).exists()
    batch = list(tmp_path.glob("forensics-batch-report-*.md"))
    assert len(batch) == 1 and "Executive summary" in batch[0].read_text(encoding="utf-8")


def test_save_modes(tmp_path, monkeypatch):
    doc = tmp_path / "x.pdf"
    doc.write_bytes(pdfgen.build())
    sh = ForensicsShell(colour=False)
    sh.interactive = True
    monkeypatch.setattr(builtins, "input", lambda *_: (_ for _ in ()).throw(AssertionError("must not ask")))
    sh.onecmd("set save always")
    sh.onecmd(f'"{doc}"')
    assert len(list(tmp_path.glob("x.pdf.forensics-report*.md"))) == 1
    sh.onecmd("set save never")
    sh.onecmd(f'"{doc}"')
    assert len(list(tmp_path.glob("x.pdf.forensics-report*.md"))) == 1


def test_non_interactive_shell_does_not_ask(tmp_path, monkeypatch):
    doc = tmp_path / "x.pdf"
    doc.write_bytes(pdfgen.build())
    sh = ForensicsShell(colour=False)            # stdin is not a TTY under pytest
    monkeypatch.setattr(builtins, "input", lambda *_: (_ for _ in ()).throw(AssertionError("must not ask")))
    sh.onecmd(f'"{doc}"')
    assert list(tmp_path.glob("*" + SUFFIX)) == []


def test_cli_save_report_flag(tmp_path, capsys):
    doc = tmp_path / "inv.pdf"
    doc.write_bytes(_tampered())
    assert main(["analyze", str(doc), "--summary", "--save-report"]) == 0
    assert (tmp_path / ("inv.pdf" + SUFFIX)).exists()
    assert "report saved:" in capsys.readouterr().err


def test_unwritable_folder_is_reported_not_raised(tmp_path, monkeypatch):
    doc = tmp_path / "a.pdf"
    doc.write_bytes(pdfgen.build())
    from pdfforensics.engine import analyze_file
    r = analyze_file(doc).to_dict()

    def boom(self, *a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(type(tmp_path), "write_text", boom)
    written, errors = save_reports([r])
    assert written == [] and "Permission denied" in errors[0]
