import io
import sys

import officegen as og
import pdfgen
from pdfforensics import __version__
from pdfforensics.cli import main
from pdfforensics.repl import ForensicsShell, banner


def _tampered() -> bytes:
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    return pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK"))})


def test_banner_is_a_closed_box_with_name_and_version():
    lines = banner().splitlines()
    assert len({len(line) for line in lines}) == 1          # all rows equally wide
    assert set(lines[0]) == {"#"} and set(lines[-1]) == {"#"}
    assert all(line.startswith("#") and line.endswith("#") for line in lines)
    assert any(f"pdf-forensics-kit {__version__}" in line for line in lines)


def test_bare_path_is_analysed(tmp_path, capsys):
    p = tmp_path / "invoice.pdf"
    p.write_bytes(_tampered())
    sh = ForensicsShell(colour=False)
    assert sh.onecmd(str(p)) is False
    out = capsys.readouterr().out
    assert "invoice.pdf: significant-indicators" in out and "Total: 900 SEK" in out


def test_path_named_like_a_command_is_still_a_file(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "report.pdf").write_bytes(pdfgen.build())
    ForensicsShell(colour=False).onecmd("report.pdf")
    assert "report.pdf: no-indicators" in capsys.readouterr().out


def test_drag_and_drop_escaped_spaces(tmp_path, capsys):
    d = tmp_path / "Case files"
    d.mkdir()
    (d / "my offer.docx").write_bytes(og.build("docx"))
    ForensicsShell(colour=False).onecmd(str(d / "my offer.docx").replace(" ", "\\ "))
    assert "my offer.docx: no-indicators" in capsys.readouterr().out


def test_session_flow_outdir_last_findings(tmp_path, capsys):
    p = tmp_path / "a.pdf"
    p.write_bytes(_tampered())
    sh = ForensicsShell(colour=False)
    sh.onecmd(f"set outdir {tmp_path / 'reports'}")
    sh.onecmd(f"analyze {p}")
    assert len(list((tmp_path / "reports").glob("a.pdf.*.summary.md"))) == 1
    capsys.readouterr()
    sh.onecmd("findings high")
    out = capsys.readouterr().out
    assert "[HIGH]" in out and "revisions.content-changed" in out
    sh.onecmd("last")
    assert "# Summary: a.pdf" in capsys.readouterr().out
    sh.onecmd("status")
    assert "output folder" in capsys.readouterr().out


def test_report_extract_compare(tmp_path, capsys):
    p = tmp_path / "inv.pdf"
    p.write_bytes(_tampered())
    sh = ForensicsShell(colour=False)
    sh.onecmd(f"report {p}")
    assert "## Findings" in capsys.readouterr().out
    sh.onecmd(f"extract {p} {tmp_path / 'revs'}")
    revs = sorted((tmp_path / "revs").iterdir())
    assert len(revs) == 2
    capsys.readouterr()
    sh.onecmd(f"compare {revs[0]} {p}")
    assert "900 SEK" in capsys.readouterr().out


def test_errors_do_not_leave_the_shell(tmp_path, capsys):
    sh = ForensicsShell(colour=False)
    for line in ("frobnicate", "compare onlyone", f"compare {tmp_path}/nope.pdf {tmp_path}/nope2.pdf",
                 "set online maybe-later", "findings bogus", "set colour red", "analyze", "last"):
        assert not sh.onecmd(line), line   # a falsy return keeps the shell running
    out = capsys.readouterr().out
    assert "unknown command" in out and "usage: compare A B" in out


def test_settings_change_options(capsys):
    sh = ForensicsShell(colour=False)
    sh.onecmd("set external off")
    sh.onecmd("set online on")
    o = sh._options()
    assert o.external_tools is False and o.online_revocation is True
    assert "network access enabled" in capsys.readouterr().out


def test_exit_and_help(capsys):
    sh = ForensicsShell(colour=False)
    sh.onecmd("help")
    sh.onecmd("help extract")
    out = capsys.readouterr().out
    assert "drag a file or folder" in out and "Write every revision" in out
    assert sh.onecmd("exit") is True
    assert sh.onecmd("q") is True
    assert sh.onecmd("EOF") is True


def test_no_arguments_starts_shell_with_piped_commands(tmp_path, capsys, monkeypatch):
    p = tmp_path / "x.pdf"
    p.write_bytes(pdfgen.build())
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"analyze {p}\nexit\n"))
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "x.pdf: no-indicators" in out and "bye" in out


def test_path_completion(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "invoice-2026.pdf").write_bytes(b"x")
    (tmp_path / "invoices").mkdir()
    sh = ForensicsShell(colour=False)
    assert sh.complete_analyze("inv", "analyze inv", 8, 11) == ["invoice-2026.pdf", "invoices/"]
    assert sh.complete_set("ou", "set ou", 4, 6) == ["outdir"]
    assert sh.complete_set("o", "set external o", 13, 14) == ["on", "off"]
