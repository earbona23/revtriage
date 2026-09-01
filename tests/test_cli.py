"""CLI smoke tests: it reads a file, writes the requested format, and never executes it."""

from __future__ import annotations

import json

from revtriage import cli


def test_cli_markdown_to_stdout(corpus, tmp_path, capsys):
    sample = tmp_path / "dropper.ps1"
    sample.write_bytes(corpus["powershell_dropper.ps1"])
    rc = cli.main([str(sample)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Verdict:" in out


def test_cli_json_format(corpus, tmp_path, capsys):
    sample = tmp_path / "s.ps1"
    sample.write_bytes(corpus["powershell_dropper.ps1"])
    rc = cli.main([str(sample), "-f", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score"]["verdict"]


def test_cli_writes_all_formats(corpus, tmp_path):
    sample = tmp_path / "s.ps1"
    sample.write_bytes(corpus["powershell_dropper.ps1"])
    base = tmp_path / "report"
    rc = cli.main([str(sample), "-f", "all", "-o", str(base)])
    assert rc == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()
    stix = json.loads((tmp_path / "report.stix.json").read_text())
    assert stix["type"] == "bundle"


def test_cli_exit_code_reflects_verdict(corpus, tmp_path):
    sample = tmp_path / "s.ps1"
    sample.write_bytes(corpus["powershell_dropper.ps1"])
    rc = cli.main([str(sample), "-f", "json", "--exit-code"])
    assert rc in (20, 30)  # likely-malicious or malicious


def test_cli_missing_file_returns_error(tmp_path):
    rc = cli.main([str(tmp_path / "nope.bin")])
    assert rc == 2
