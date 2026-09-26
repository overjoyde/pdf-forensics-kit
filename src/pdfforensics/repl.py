"""Interactive shell: ``pdfforensics`` (no arguments) or ``pdfforensics shell``.

Type a command, or just drag a file or folder into the terminal and press Enter to analyse it.
Session settings (output folder, external tools) persist until you leave.
"""

from __future__ import annotations

import cmd
import contextlib
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from pdfforensics import __version__, render
from pdfforensics.document import InputError, Options

HISTORY_FILE = Path.home() / ".pdfforensics_history"
TAGLINE = "PDF & Office tampering analysis - local, read-only"
SEV_COLOURS = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "1;33", "LOW": "36", "INFO": "2"}
VERDICT_COLOURS = {"strong-indicators": "1;97;41", "significant-indicators": "1;31",
                   "review-recommended": "1;33", "minor-anomalies": "36", "no-indicators": "1;32"}


def split_args(line: str) -> list[str]:
    """Split a command line into arguments.

    POSIX shells (macOS, Linux) drag-and-drop paths with backslash-escaped spaces, which shlex
    handles. On Windows, backslashes are path separators, so quotes are the only grouping.
    """
    if os.name == "nt":
        parts = shlex.split(line, posix=False)
        return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
    return shlex.split(line)


def whole_line_path(line: str) -> str | None:
    """The entire input as one existing path (unquoted paths with spaces, quoted drops)."""
    cand = os.path.expanduser(line.strip().strip("\"'"))
    return cand if cand and Path(cand).exists() else None


# ------------------------------------------------------------------------------------ banner

def banner(width: int = 46) -> str:
    """Boxed banner with the tool name and version, e.g.

    ##############################################
    #                                            #
    #          pdf-forensics-kit 0.4.0           #
    # PDF & Office tampering analysis - local... #
    #                                            #
    ##############################################
    """
    lines = [f"pdf-forensics-kit {__version__}", TAGLINE]
    inner = max(width - 2, max(len(s) for s in lines) + 4)
    edge = "#" * (inner + 2)
    blank = "#" + " " * inner + "#"
    body = ["#" + s.center(inner) + "#" for s in lines]
    return "\n".join([edge, blank, *body, blank, edge])


def _colour_enabled(stream: Any) -> bool:
    return (hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")
            and os.environ.get("TERM") != "dumb")


def _c(text: str, code: str, on: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if on else text


def pretty(md: str, on: bool) -> str:
    """Light terminal styling for the Markdown the tool produces (no-op without colour)."""
    if not on:
        return md
    out = []
    for line in md.splitlines():
        if line.startswith("#"):
            line = _c(line.lstrip("# "), "1;4", True)
        else:
            line = re.sub(r"\*\*(.+?)\*\*", lambda m: _c(m.group(1), "1", True), line)
            line = re.sub(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]",
                          lambda m: _c(f"[{m.group(1)}]", SEV_COLOURS[m.group(1)], True), line)
            line = re.sub(r"`([a-z-]+-indicators|review-recommended|minor-anomalies)`",
                          lambda m: _c(m.group(1), VERDICT_COLOURS.get(m.group(1), "1"), True), line)
            line = re.sub(r"(?<!\w)_(.+?)_(?!\w)", lambda m: _c(m.group(1), "2", True), line)
        out.append(line)
    return "\n".join(out)


# ------------------------------------------------------------------------------------ shell

class ForensicsShell(cmd.Cmd):
    intro = ""
    doc_header = "Commands (type 'help <command>' for details)"

    def __init__(self, colour: bool | None = None) -> None:
        super().__init__()
        self.colour = _colour_enabled(sys.stdout) if colour is None else colour
        self.prompt = self._prompt_text()
        self.outdir: Path | None = None
        self.external = True
        self.online = False
        self.recursive = True
        self.last: list[dict] = []
        self.last_failures: list[dict] = []

    # -------------------------------------------------------------- helpers
    def _prompt_text(self) -> str:
        if not self.colour:
            return "pdfforensics › "

        # \001 ... \002 mark escape codes as zero-width so readline computes the cursor position correctly
        def z(code: str) -> str:
            return f"\001\033[{code}m\002"

        return f"{z('1;36')}pdfforensics{z('0')}{z('2')} › {z('0')}"

    def out(self, text: str = "") -> None:
        print(text, file=sys.stdout)

    def err(self, text: str) -> None:
        print(_c(f"✗ {text}", "31", self.colour), file=sys.stdout)

    def ok(self, text: str) -> None:
        print(_c(f"✓ {text}", "32", self.colour), file=sys.stdout)

    def _options(self) -> Options:
        return Options(external_tools=self.external, online_revocation=self.online)

    def _split(self, line: str) -> list[str] | None:
        try:
            return split_args(line)
        except ValueError as exc:
            self.err(f"could not parse input: {exc}")
            return None

    def _cli(self, argv: list[str]) -> int:
        """Run a normal CLI command inside the shell, never letting it exit the shell."""
        from pdfforensics.cli import main

        if not self.external:
            argv = argv + ["--no-external-tools"]
        if self.online:
            argv = argv + ["--online-revocation"]
        try:
            return main(argv)
        except SystemExit as exc:  # argparse errors / --help
            return int(exc.code or 0) if isinstance(exc.code, int) else 2

    def _analyse(self, paths: list[str], full: bool) -> None:
        from pdfforensics.cli import _collect, _summary_doc, report_basename
        from pdfforensics.engine import analyze_file

        files = _collect(paths, self.recursive)
        if not files:
            self.err("no supported documents found (PDF, DOCX, XLSX, PPTX, ...)")
            return
        reports, failures = [], []
        for i, f in enumerate(files, 1):
            if len(files) > 1:
                print(_c(f"  [{i}/{len(files)}] {f.name}", "2", self.colour), file=sys.stderr)
            try:
                reports.append(analyze_file(f, self._options()).to_dict())
            except InputError as exc:
                failures.append({"file": str(f), "error": str(exc)})
        self.last, self.last_failures = reports, failures
        for fl in failures:
            self.err(f"{fl['file']}: {fl['error']}")
        if not reports:
            return
        if full and len(reports) == 1:
            text = render.report_markdown(reports[0])
        else:
            text = _summary_doc(reports, failures)
        self.out(pretty(text, self.colour))
        if self.outdir:
            self.outdir.mkdir(parents=True, exist_ok=True)
            for r in reports:
                base = report_basename(r)
                (self.outdir / f"{base}.forensics.json").write_text(render.to_json(r) + "\n", encoding="utf-8")
                (self.outdir / f"{base}.forensics.md").write_text(render.report_markdown(r) + "\n", encoding="utf-8")
                (self.outdir / f"{base}.summary.md").write_text(_summary_doc([r], []) + "\n", encoding="utf-8")
            if len(reports) + len(failures) > 1:
                (self.outdir / "batch-summary.md").write_text(render.batch_markdown(reports, failures),
                                                              encoding="utf-8")
            self.ok(f"reports saved in {self.outdir}")

    # -------------------------------------------------------------- lifecycle
    def preloop(self) -> None:
        try:
            import readline

            if "libedit" in (readline.__doc__ or ""):
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
            readline.set_completer_delims(" \t\n;")
            if HISTORY_FILE.exists():
                readline.read_history_file(HISTORY_FILE)
            readline.set_history_length(1000)
        except Exception:
            pass

    def postloop(self) -> None:
        try:
            import readline

            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

    def emptyline(self) -> bool:
        return False

    def onecmd(self, line: str) -> bool:
        # Existing paths win over command names (a file called 'report.pdf' is a file, not 'report').
        stripped = line.strip()
        if stripped and stripped.split()[0] not in ("help", "?"):
            whole = whole_line_path(stripped)
            if whole:
                self._analyse([whole], full=False)
                return False
            try:
                args = split_args(stripped)
            except ValueError:
                args = []
            if args and all(Path(os.path.expanduser(a)).exists() for a in args):
                self._analyse([os.path.expanduser(a) for a in args], full=False)
                return False
        try:
            return super().onecmd(line)
        except KeyboardInterrupt:
            self.out("")
            self.err("interrupted")
            return False

    def default(self, line: str) -> bool:
        """A bare path (e.g. dragged into the terminal) is analysed; anything else is unknown."""
        args = self._split(line)
        if args is None:
            return False
        if args and all(Path(os.path.expanduser(a)).exists() for a in args):
            self._analyse([os.path.expanduser(a) for a in args], full=False)
        else:
            self.err(f"unknown command: {args[0] if args else line}. Type 'help'.")
        return False

    # -------------------------------------------------------------- commands
    def do_analyze(self, line: str) -> None:
        """analyze PATH [PATH ...]
    Analyse files or folders (recursively) and show the summary.
    Tip: you can also just drag a file or folder into the terminal and press Enter."""
        args = self._split(line)
        if args is None:
            return
        if not args:
            self.err("usage: analyze PATH [PATH ...]")
            return
        self._analyse([os.path.expanduser(a) for a in args], full=False)

    do_a = do_analyze

    def do_report(self, line: str) -> None:
        """report PATH
    Analyse one document and show the full report (every finding with its evidence)."""
        args = self._split(line)
        if not args:
            self.err("usage: report PATH")
            return
        self._analyse([os.path.expanduser(a) for a in args], full=True)

    def do_last(self, line: str) -> None:
        """last [full]
    Show the result of the previous analysis again ('last full' shows the complete report)."""
        from pdfforensics.cli import _summary_doc

        if not self.last:
            self.err("nothing analysed yet in this session")
            return
        if line.strip() == "full":
            for r in self.last:
                self.out(pretty(render.report_markdown(r), self.colour))
        else:
            self.out(pretty(_summary_doc(self.last, self.last_failures), self.colour))

    def do_findings(self, line: str) -> None:
        """findings [LEVEL]
    List the findings of the previous analysis at or above LEVEL (default: low)."""
        order = ["info", "low", "medium", "high", "critical"]
        level = (line.strip() or "low").lower()
        if level not in order:
            self.err(f"level must be one of {', '.join(order)}")
            return
        if not self.last:
            self.err("nothing analysed yet in this session")
            return
        for r in self.last:
            self.out(_c(f"{r['file']['name']}  ", "1", self.colour)
                     + _c(r["verdict"]["label"], VERDICT_COLOURS.get(r["verdict"]["label"], "1"), self.colour))
            shown = [f for f in r["findings"] if order.index(f["severity"]) >= order.index(level)]
            for f in shown:
                tag = f["severity"].upper()
                self.out(f"  {_c(f'[{tag}]', SEV_COLOURS[tag], self.colour)} {f['title']}  "
                         + _c(f"({f['id']}, confidence {f['confidence']})", "2", self.colour))
            if not shown:
                self.out(_c("  (none at this level)", "2", self.colour))

    def do_extract(self, line: str) -> None:
        """extract PDF [OUTDIR]
    Write every revision of a PDF as a standalone file (default OUTDIR: ./revisions)."""
        args = self._split(line)
        if not args:
            self.err("usage: extract PDF [OUTDIR]")
            return
        outdir = args[1] if len(args) > 1 else str(self.outdir / "revisions" if self.outdir else "revisions")
        self._cli(["extract-revisions", os.path.expanduser(args[0]), "--out-dir", os.path.expanduser(outdir)])

    def do_compare(self, line: str) -> None:
        """compare A B
    Compare two PDFs: identity, metadata, production pipeline and page text."""
        args = self._split(line)
        if not args or len(args) != 2:
            self.err("usage: compare A B")
            return
        self._cli(["compare", *(os.path.expanduser(a) for a in args)])

    def do_summarize(self, line: str) -> None:
        """summarize REPORT.forensics.json [...]
    Rebuild summaries from saved JSON reports."""
        args = self._split(line)
        if not args:
            self.err("usage: summarize REPORT.forensics.json [...]")
            return
        from pdfforensics.cli import main

        with contextlib.suppress(SystemExit):  # summarize takes no analysis options
            main(["summarize", *(os.path.expanduser(a) for a in args)])

    def do_set(self, line: str) -> None:
        """set outdir DIR|off     save JSON/Markdown/summary files for every analysis in DIR
    set external on|off     use Poppler pdfsig as a second signature validator (default on)
    set online on|off       allow pdfsig to contact OCSP servers - NETWORK ACCESS (default off)
    set recursive on|off    include sub-folders when analysing a folder (default on)"""
        args = self._split(line)
        if not args or len(args) != 2:
            self.err("usage: set outdir DIR|off | set external on|off | set online on|off | set recursive on|off")
            return
        key, val = args[0].lower(), args[1]
        flag = val.lower() in ("on", "yes", "true", "1")
        if key == "outdir":
            self.outdir = None if val.lower() == "off" else Path(os.path.expanduser(val)).resolve()
            self.ok(f"output folder: {self.outdir or 'off (results only shown on screen)'}")
        elif key == "external":
            self.external = flag
            self.ok(f"external tools (pdfsig): {'on' if flag else 'off'}")
        elif key == "online":
            self.online = flag
            if flag:
                self.out(_c("! network access enabled: pdfsig may contact certificate OCSP servers", "1;33",
                            self.colour))
            self.ok(f"online revocation checks: {'on' if flag else 'off'}")
        elif key == "recursive":
            self.recursive = flag
            self.ok(f"recursive folders: {'on' if flag else 'off'}")
        else:
            self.err(f"unknown setting: {key}")

    def do_status(self, line: str) -> None:
        """status
    Show the session settings and which validators are available."""
        from pdfforensics.analyzers.pdfsig import find_pdfsig
        from pdfforensics.analyzers.signatures import HAVE_PYHANKO

        rows = [
            ("version", __version__),
            ("output folder", str(self.outdir) if self.outdir else "off (screen only)"),
            ("recursive folders", "on" if self.recursive else "off"),
            ("pyHanko signatures", "available" if HAVE_PYHANKO else "not installed"),
            ("pdfsig (Poppler)", ("available" if find_pdfsig() else "not installed")
             + ("" if self.external else ", disabled")),
            ("network access", "ON (OCSP)" if self.online else "off"),
            ("analysed this session", str(len(self.last)) + " (last batch)"),
        ]
        for k, v in rows:
            self.out(f"  {k:<22} {v}")

    def do_clear(self, line: str) -> None:
        """clear
    Clear the screen and show the banner again."""
        self.out("\033[2J\033[H" if self.colour else "")
        self.out(_c(banner(), "1;36", self.colour))

    def do_help(self, arg: str) -> None:
        """help [COMMAND]
    Show the list of commands, or help for one command."""
        if arg:
            fn = getattr(self, f"do_{arg}", None)
            if fn and fn.__doc__:
                self.out("  " + fn.__doc__.strip())
            else:
                self.err(f"no help for {arg!r}")
            return
        self.out(_c("Commands", "1", self.colour))
        for name, text in [
            ("<path>", "drag a file or folder in and press Enter to analyse it"),
            ("analyze PATH...", "analyse files/folders and show the summary (alias: a)"),
            ("report PATH", "full report with every finding and its evidence"),
            ("last [full]", "show the previous result again"),
            ("findings [LEVEL]", "list findings of the previous analysis (info|low|medium|high|critical)"),
            ("extract PDF [DIR]", "recover every earlier revision of a PDF as separate files"),
            ("compare A B", "compare two PDFs (metadata, production, text)"),
            ("summarize JSON...", "rebuild summaries from saved JSON reports"),
            ("set KEY VALUE", "outdir DIR|off, external on|off, online on|off, recursive on|off"),
            ("status", "session settings and available validators"),
            ("clear", "clear the screen"),
            ("exit", "leave (also: quit, q, Ctrl-D)"),
        ]:
            self.out(f"  {_c(name, '36', self.colour):<{30 if self.colour else 21}} {text}")

    def do_exit(self, line: str) -> bool:
        """exit
    Leave the forensics shell."""
        self.out(_c("bye - reports stay where you saved them.", "2", self.colour))
        return True

    do_quit = do_q = do_exit

    def do_EOF(self, line: str) -> bool:  # Ctrl-D
        self.out("")
        return self.do_exit(line)

    # -------------------------------------------------------------- completion
    def _complete_path(self, text: str, *_: Any) -> list[str]:
        expanded = os.path.expanduser(text)
        base = os.path.dirname(expanded) or "."
        prefix = os.path.basename(expanded)
        try:
            entries = os.listdir(base)
        except OSError:
            return []
        out = []
        for e in sorted(entries):
            if e.startswith(prefix) and not (e.startswith(".") and not prefix.startswith(".")):
                full = os.path.join(os.path.dirname(text), e) if os.path.dirname(text) else e
                out.append(full + ("/" if os.path.isdir(os.path.join(base, e)) else ""))
        return out

    complete_analyze = complete_a = complete_report = complete_extract = complete_compare = \
        complete_summarize = completedefault = _complete_path

    def complete_set(self, text: str, line: str, *_: Any) -> list[str]:
        parts = line.split()
        if len(parts) <= 1 or (len(parts) == 2 and not line.endswith(" ")):
            return [k for k in ("outdir", "external", "online", "recursive") if k.startswith(text)]
        if parts[1] == "outdir":
            return self._complete_path(text)
        return [v for v in ("on", "off") if v.startswith(text)]


def run() -> int:
    shell = ForensicsShell()
    interactive = sys.stdin.isatty()
    if interactive:
        shell.out(_c(banner(), "1;36", shell.colour))
        shell.out(_c("  Drag a file or folder here and press Enter, or type 'help'. 'exit' to leave.\n",
                     "2", shell.colour))
    else:
        shell.prompt = ""
    while True:
        try:
            shell.cmdloop()
            return 0
        except KeyboardInterrupt:  # Ctrl-C at the prompt: clear the line, keep the shell
            shell.out("^C  (type 'exit' or press Ctrl-D to leave)")
