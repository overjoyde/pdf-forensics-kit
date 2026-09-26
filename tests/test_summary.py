import json

import pdfgen
from pdfforensics.cli import main
from pdfforensics.summary import batch_summary, summarize


def _tampered() -> bytes:
    base = pdfgen.build()
    num = pdfgen.content_objnum(base)
    return pdfgen.append_update(base, {num: pdfgen.stream_obj(pdfgen.text_stream("Invoice 2026-001", "Total: 900 SEK"))})


def test_summary_is_part_of_every_report(analyze):
    r = analyze(pdfgen.build())
    s = r["summary"]
    assert s["verdict"] == "no-indicators"
    assert s["headline"].startswith("doc.pdf: no-indicators - no significant findings")
    assert not s["key_findings"]
    assert "No page content was changed through appended edits." in s["ruled_out"]
    assert "not digitally signed" in s["document"]
    assert s["limitations"][-1].startswith("Structural analysis cannot prove")


def test_summary_explains_content_change_with_evidence_and_action(analyze):
    s = analyze(_tampered())["summary"]
    assert "1 finding(s) need attention (1 high)" in s["headline"]
    k = s["key_findings"][0]
    assert k["id"] == "revisions.content-changed"
    assert '"Total: 100 SEK"' in k["evidence"] and '"Total: 900 SEK"' in k["evidence"]
    assert any("extract-revisions" in a for a in s["recommended_actions"])
    assert "1 later edit(s) appended" in s["document"]
    assert not any("appended edits" in x for x in s["ruled_out"])


def test_summary_is_reproducible_from_saved_json(analyze):
    r = analyze(_tampered())
    reloaded = json.loads(json.dumps(r, default=str))
    assert summarize(reloaded) == r["summary"]


def test_incomplete_analysis_is_stated_in_limitations(analyze):
    r = analyze(pdfgen.build())
    r["verdict"]["complete"] = False
    r["errors"] = [{"analyzer": "content", "error": "boom"}]
    assert any("Analysis incomplete: content" in x for x in summarize(r)["limitations"])


def test_batch_summary_orders_by_severity(analyze):
    reports = [analyze(pdfgen.build(), "clean.pdf"),
               analyze(pdfgen.build(producer="iLovePDF"), "editor.pdf"),
               analyze(_tampered(), "tampered.pdf")]
    b = batch_summary(reports, [{"file": "broken.pdf", "error": "not a PDF"}])
    assert b["headline"] == ("4 document(s) submitted: 2 need attention, 1 without significant findings, "
                             "1 could not be analysed.")
    assert [x["file"] for x in b["needs_attention"]] == ["tampered.pdf", "editor.pdf"]


def test_cli_summary_flag_prints_only_summary(tmp_path, capsys):
    p = tmp_path / "inv.pdf"
    p.write_bytes(_tampered())
    assert main(["analyze", str(p), "--summary"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Summary: inv.pdf")
    assert "Recommended next steps" in out and "## Findings" not in out


def test_cli_out_dir_writes_summary_files(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "a.pdf").write_bytes(pdfgen.build())
    (src / "b.pdf").write_bytes(_tampered())
    out = tmp_path / "out"
    assert main(["analyze", str(src), "--out-dir", str(out)]) == 0
    assert (out / "b.summary.md").read_text().startswith("# Summary: b.pdf")
    batch = (out / "batch-summary.md").read_text()
    assert "## Executive summary" in batch and "b.pdf: `significant-indicators`" in batch


def test_cli_summarize_regenerates_from_json(tmp_path, capsys):
    p = tmp_path / "inv.pdf"
    p.write_bytes(_tampered())
    j = tmp_path / "inv.forensics.json"
    assert main(["analyze", str(p), "--json", str(j)]) == 0
    md, sj = tmp_path / "s.md", tmp_path / "s.json"
    assert main(["summarize", str(j), "-o", str(md), "--json", str(sj)]) == 0
    assert "Total: 900 SEK" in md.read_text()
    assert json.loads(sj.read_text())["documents"][0]["verdict"] == "significant-indicators"
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    assert main(["summarize", str(bad)]) == 2
