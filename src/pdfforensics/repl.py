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
SEV_COLOURS = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "1;33", "LOW": "36", "INFO": "2"}
VERDICT_CHIPS = {"strong-indicators": "1;97;48;5;160", "significant-indicators": "1;97;48;5;196",
                 "review-recommended": "1;30;48;5;214", "minor-anomalies": "1;30;48;5;80",
                 "no-indicators": "1;30;48;5;42"}
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

# Two-row half-block font: each glyph is (top, bottom), equal width per glyph.
GLYPHS = {
    "P": ("█▀█", "█▀▀"), "D": ("█▀▄", "█▄▀"), "F": ("█▀▀", "█▀ "), "O": ("█▀█", "█▄█"),
    "R": ("█▀█", "█▀▄"), "E": ("█▀▀", "██▄"), "N": ("█▄ █", "█ ▀█"), "S": ("█▀", "▄█"),
    "I": ("█", "█"), "C": ("█▀▀", "█▄▄"), " ": ("  ", "  "),
}
LOGO_TEXT = "PDF FORENSICS"
# gradient stops (cyan -> blue -> violet -> magenta)
GRADIENT = [(0, 229, 255), (41, 121, 255), (124, 77, 255), (224, 64, 251)]
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _logo_rows() -> tuple[str, str]:
    top = " ".join(GLYPHS[ch][0] for ch in LOGO_TEXT)
    bot = " ".join(GLYPHS[ch][1] for ch in LOGO_TEXT)
    return top, bot


def _truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


def _lerp(stops: list[tuple[int, int, int]], t: float) -> tuple[int, int, int]:
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(t), len(stops) - 2)
    f = t - i
    a, b = stops[i], stops[i + 1]
    return tuple(round(a[k] + (b[k] - a[k]) * f) for k in range(3))  # type: ignore[return-value]


def _rgb_code(rgb: tuple[int, int, int], truecolor: bool) -> str:
    if truecolor:
        return "38;2;%d;%d;%d" % rgb
    r, g, b = (round(v / 255 * 5) for v in rgb)  # 6x6x6 cube of the 256-colour palette
    return "38;5;%d" % (16 + 36 * r + 6 * g + b)


def gradient(text: str, on: bool, truecolor: bool | None = None, bold: bool = True) -> str:
    """Colour text with a horizontal gradient (per character); spaces stay uncoloured."""
    if not on:
        return text
    tc = _truecolor() if truecolor is None else truecolor
    n = max(len(text) - 1, 1)
    out = []
    for i, ch in enumerate(text):
        if ch == " ":
            out.append(ch)
        else:
            out.append(f"\033[{'1;' if bold else ''}{_rgb_code(_lerp(GRADIENT, i / n), tc)}m{ch}")
    return "".join(out) + "\033[0m"


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def _unicode_ok(stream: Any = None) -> bool:
    enc = getattr(stream or sys.stdout, "encoding", None) or "ascii"
    try:
        "╭█▀▄●✓❯".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def banner(colour: bool = False, unicode: bool | None = None, status: list[tuple[str, bool]] | None = None) -> str:
    """Start-up banner: gradient block logo in a rounded panel, tagline, version and badges.

    ╭─────────────────────────────────────────────────────────╮
    │                                                         │
    │   █▀█ █▀▄ █▀▀   █▀▀ █▀█ █▀█ █▀▀ █▄ █ █▀ █ █▀▀ █▀        │
    │   █▀▀ █▄▀ █▀    █▀  █▄█ █▀▄ ██▄ █ ▀█ ▄█ █ █▄▄ ▄█  kit   │
    │                                                         │
    │   pdf-forensics-kit · PDF & Office tampering    v0.6.0  │
    │   ● local   ● read-only   ● no uploads                  │
    │                                                         │
    ╰─────────────────────────────────────────────────────────╯

    Falls back to plain ASCII when the terminal cannot show Unicode, and to no colour
    when colour is off (NO_COLOR, pipes, dumb terminals).
    """
    uni = _unicode_ok() if unicode is None else unicode
    ver = f"v{__version__}"
    if uni:
        tl, tr, bl, br, h, v, dot = "╭", "╮", "╰", "╯", "─", "│", "●"
        top, bot = _logo_rows()
        logo = [top, bot + "  kit"]
    else:
        tl, tr, bl, br, h, v, dot = "+", "+", "+", "+", "-", "|", "*"
        logo = ["P D F   F O R E N S I C S   kit"]
    tagline = "pdf-forensics-kit · PDF & Office tampering analysis" if uni else \
        "pdf-forensics-kit - PDF & Office tampering analysis"
    badges = [f"{dot} local", f"{dot} read-only", f"{dot} no uploads"]
    pad = 3
    inner = max(max(len(x) for x in logo), len(tagline) + 2 + len(ver), len("   ".join(badges))) + 2 * pad

    def dim(t: str) -> str:
        return _c(t, "38;5;240", colour)

    def row(content: str = "", plain_len: int | None = None) -> str:
        n = visible_len(content) if plain_len is None else plain_len
        return dim(v) + " " * pad + content + " " * (inner - pad - n) + dim(v)

    lines = [dim(tl + h * inner + tr), row()]
    width_logo = max(len(x) for x in logo)
    left = (inner - width_logo) // 2
    for x in logo:
        x = x.ljust(width_logo)
        lines.append(dim(v) + " " * left + gradient(x, colour) + " " * (inner - left - len(x)) + dim(v))
    lines.append(row())
    gap = inner - 2 * pad - len(tagline) - len(ver)
    tag = _c("pdf-forensics-kit", "1", colour) + tagline[len("pdf-forensics-kit"):]
    lines.append(row(tag + " " * gap + _c(ver, "1;38;5;141", colour), len(tagline) + gap + len(ver)))
    badge_cols = ["38;5;42", "38;5;39", "38;5;213"]
    btxt = "   ".join(_c(b[:1], c, colour) + _c(b[1:], "38;5;250", colour) for b, c in zip(badges, badge_cols))
    lines.append(row(btxt, len("   ".join(badges))))
    lines += [row(), dim(bl + h * inner + br)]
    if status:
        ok, bad = ("✓", "✗") if uni else ("+", "-")
        parts = [(_c(ok, "1;32", colour) if good else _c(bad, "2", colour)) + " " + _c(label, "38;5;250" if good else "2", colour)
                 for label, good in status]
        lines.append("  " + "   ".join(parts))
    return "\n".join(lines)


def _libedit() -> bool:
    try:
        import readline
    except ImportError:
        return False
    return "libedit" in (readline.__doc__ or "")


def _colour_enabled(stream: Any) -> bool:
    return (hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")
            and os.environ.get("TERM") != "dumb")


def _c(text: str, code: str, on: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if on else text


VERDICT_RE = re.compile(r"`?\b(strong-indicators|significant-indicators|review-recommended|minor-anomalies|"
                        r"no-indicators)\b`?")
SEV_BADGES = {"CRITICAL": "1;97;48;5;160", "HIGH": "1;97;48;5;196", "MEDIUM": "1;30;48;5;214",
              "LOW": "1;30;48;5;80", "INFO": "30;48;5;245"}


def wrap_ansi(line: str, width: int) -> list[str]:
    """Word-wrap a (possibly coloured) line to the visible width, with a hanging indent
    for bullets and numbered steps."""
    if width < 20 or visible_len(line) <= width:
        return [line]
    plain = ANSI_RE.sub("", line)
    m = re.match(r"^(\s*(?:[•\-]|\d+\.)?\s*)", plain)
    hang = " " * len(m.group(1)) if m else ""
    lead = line[:len(line) - len(line.lstrip(" "))]
    words = line.lstrip(" ").split(" ")
    words[0] = lead + words[0]
    rows, cur, cur_len = [], "", 0
    for w in words:
        wl = visible_len(w)
        if cur and cur_len + 1 + wl > width:
            rows.append(cur)
            cur, cur_len = hang + w, len(hang) + wl
        else:
            cur = f"{cur} {w}" if cur else w
            cur_len += (1 if cur_len else 0) + wl
    rows.append(cur)
    return rows


def pretty(md: str, on: bool, width: int | None = None) -> str:
    """Terminal styling for the Markdown the tool produces (no-op without colour).

    Headings get an accent bar, verdict labels are coloured chips, severities are badges,
    list dashes become bullets and inline code is shown in cyan without backticks.
    """
    if width is None:
        import shutil

        width = shutil.get_terminal_size((100, 24)).columns - 1
    if not on:
        return "\n".join(r for line in md.splitlines() for r in wrap_ansi(line, width))
    out = []
    for line in md.splitlines():
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            title = line.lstrip("# ")
            line = (gradient("▌ " + title, True) if level == 1 else _c("▎ " + title, "1;38;5;141", True))
        else:
            line = re.sub(r"^(\s*)- ", lambda m: m.group(1) + _c("• ", "38;5;141", True), line)
            line = re.sub(r"^(\d+)\. ", lambda m: _c(f"{m.group(1)}.", "1;38;5;141", True) + " ", line)
            line = re.sub(r"\*\*(.+?)\*\*", lambda m: _c(m.group(1), "1", True), line)
            line = re.sub(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]",
                          lambda m: _c(f" {m.group(1)} ", SEV_BADGES[m.group(1)], True), line)
            line = VERDICT_RE.sub(lambda m: _c(f" {m.group(1)} ", VERDICT_CHIPS[m.group(1)], True), line)
            line = re.sub(r"`([^`]+)`", lambda m: _c(m.group(1), "38;5;80", True), line)
            line = re.sub(r"(?<!\w)_(.+?)_(?!\w)", lambda m: _c(m.group(1), "2", True), line)
        out.extend(wrap_ansi(line, width))
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
        self.save_mode = "ask"            # ask | always | never: save a Markdown report next to the document
        self.interactive = sys.stdin.isatty()
        self.last: list[dict] = []
        self.last_failures: list[dict] = []

    # -------------------------------------------------------------- helpers
    def _prompt_text(self) -> str:
        uni = _unicode_ok()
        mark, arrow = ("◆", "❯") if uni else ("*", ">")
        if not self.colour or _libedit():
            # macOS libedit mishandles zero-width markers (it emits all colour codes before the prompt
            # text), so the prompt stays plain there rather than misaligning the cursor.
            return f"{mark} pdfforensics {arrow} "

        # \001 ... \002 mark escape codes as zero-width so readline computes the cursor position correctly
        def z(code: str) -> str:
            return f"\001\033[{code}m\002"

        tc = _truecolor()
        c1 = _rgb_code(GRADIENT[0], tc)
        c2 = _rgb_code(GRADIENT[2], tc)
        return (f"{z(c1)}{mark}{z('0')} {z('1;' + c1)}pdf{z('0')}{z('1;' + c2)}forensics{z('0')} "
                f"{z('38;5;213')}{arrow}{z('0')} ")

    def out(self, text: str = "") -> None:
        print(text, file=sys.stdout)

    def err(self, text: str) -> None:
        print(_c(f"✗ {text}", "31", self.colour), file=sys.stdout)

    def ok(self, text: str) -> None:
        print(_c(f"✓ {text}", "32", self.colour), file=sys.stdout)

    def _options(self) -> Options:
        return Options(external_tools=self.external, online_revocation=self.online)

    def status_badges(self) -> list[tuple[str, bool]]:
        from pdfforensics.analyzers.pdfsig import find_pdfsig
        from pdfforensics.analyzers.signatures import HAVE_PYHANKO

        return [("pyHanko signatures", HAVE_PYHANKO),
                ("pdfsig", bool(find_pdfsig()) and self.external),
                ("offline" if not self.online else "ONLINE revocation", not self.online),
                (f"saving to {self.outdir}" if self.outdir else "screen only", True),
                ({"ask": "ask to save report", "always": "auto-save report",
                  "never": "no report files"}[self.save_mode], self.save_mode != "never")]

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
        self._offer_report(reports, failures)

    def _offer_report(self, reports: list[dict], failures: list[dict]) -> None:
        """After an analysis: ask (yes/no) whether to save a Markdown report next to each document."""
        from pdfforensics.savereport import ask_yes_no, save_reports

        if not reports or self.save_mode == "never":
            return
        if self.save_mode == "ask":
            if not self.interactive:
                return
            if len(reports) == 1:
                where = Path(reports[0]["file"]["path"]).parent
                question = f"Save the report as Markdown in {where}?"
            else:
                question = f"Save {len(reports)} reports as Markdown next to the documents (+ a batch report)?"
            if not ask_yes_no("? " + question):  # plain text: libedit misplaces colour codes in input prompts
                self.out(_c("  not saved (type 'save' to save it later)", "2", self.colour))
                return
        written, errors = save_reports(reports, failures)
        for p in written:
            self.ok(f"report saved: {p}")
        for e in errors:
            self.err(e)

    def do_save(self, line: str) -> None:
        """save
    Save the report(s) of the previous analysis as Markdown next to the document(s)."""
        from pdfforensics.savereport import save_reports

        if not self.last:
            self.err("nothing analysed yet in this session")
            return
        written, errors = save_reports(self.last, self.last_failures)
        for p in written:
            self.ok(f"report saved: {p}")
        for e in errors:
            self.err(e)

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
            label = r["verdict"]["label"]
            chip = _c(f" {label} ", VERDICT_CHIPS[label], self.colour) if self.colour else label
            self.out(_c(f"{r['file']['name']}  ", "1", self.colour) + chip)
            shown = [f for f in r["findings"] if order.index(f["severity"]) >= order.index(level)]
            for f in shown:
                tag = f["severity"].upper()
                badge = _c(f" {tag} ", SEV_BADGES[tag], self.colour) if self.colour else f"[{tag}]"
                import shutil

                line = (f"  {badge} {f['title']}  "
                        + _c(f"({f['id']}, confidence {f['confidence']})", "2", self.colour))
                width = shutil.get_terminal_size((100, 24)).columns - 1
                for i, part in enumerate(wrap_ansi(line, width)):
                    self.out(part if i == 0 else "      " + part.lstrip())
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
    set recursive on|off    include sub-folders when analysing a folder (default on)
    set save ask|always|never  after each analysis: ask to save a Markdown report next to the
                               document (default), always save it, or never ask"""
        args = self._split(line)
        if not args or len(args) != 2:
            self.err("usage: set outdir DIR|off | set external on|off | set online on|off | "
                     "set recursive on|off | set save ask|always|never")
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
        elif key == "save":
            mode = {"ask": "ask", "always": "always", "on": "always", "yes": "always",
                    "never": "never", "off": "never", "no": "never"}.get(val.lower())
            if not mode:
                self.err("usage: set save ask|always|never")
                return
            self.save_mode = mode
            self.ok({"ask": "after each analysis: ask whether to save a Markdown report next to the document",
                     "always": "after each analysis: always save a Markdown report next to the document",
                     "never": "after each analysis: do not save or ask"}[mode])
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
            ("save report", {"ask": "ask after each analysis", "always": "always, next to the document",
                             "never": "never"}[self.save_mode]),
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
        self.out(banner(self.colour, status=self.status_badges()))

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
        self.out(gradient("Commands", self.colour))
        for name, text in [
            ("<path>", "drag a file or folder in and press Enter to analyse it"),
            ("analyze PATH...", "analyse files/folders and show the summary (alias: a)"),
            ("report PATH", "full report with every finding and its evidence"),
            ("last [full]", "show the previous result again"),
            ("findings [LEVEL]", "list findings of the previous analysis (info|low|medium|high|critical)"),
            ("extract PDF [DIR]", "recover every earlier revision of a PDF as separate files"),
            ("compare A B", "compare two PDFs (metadata, production, text)"),
            ("summarize JSON...", "rebuild summaries from saved JSON reports"),
            ("save", "save the last report(s) as Markdown next to the document(s)"),
            ("set KEY VALUE", "save ask|always|never, outdir DIR|off, external/online/recursive on|off"),
            ("status", "session settings and available validators"),
            ("clear", "clear the screen"),
            ("exit", "leave (also: quit, q, Ctrl-D)"),
        ]:
            self.out(f"  {_c(name.ljust(20), '1;38;5;80', self.colour)} {_c(text, '38;5;250', self.colour)}")

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
            return [k for k in ("save", "outdir", "external", "online", "recursive") if k.startswith(text)]
        if parts[1] == "outdir":
            return self._complete_path(text)
        if parts[1] == "save":
            return [v for v in ("ask", "always", "never") if v.startswith(text)]
        return [v for v in ("on", "off") if v.startswith(text)]


def run() -> int:
    shell = ForensicsShell()
    interactive = sys.stdin.isatty()
    if interactive:
        shell.out(banner(shell.colour, status=shell.status_badges()))
        shell.out(_c("  Drag a file or folder here and press Enter", "38;5;250", shell.colour)
                  + _c("  ·  ", "2", shell.colour) + _c("help", "1;38;5;141", shell.colour)
                  + _c("  ·  ", "2", shell.colour) + _c("exit", "1;38;5;141", shell.colour) + "\n")
    else:
        shell.prompt = ""
    while True:
        try:
            shell.cmdloop()
            return 0
        except KeyboardInterrupt:  # Ctrl-C at the prompt: clear the line, keep the shell
            shell.out("^C  (type 'exit' or press Ctrl-D to leave)")
