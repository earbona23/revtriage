"""Report tests: JSON round-trips, Markdown shows the honest bits, STIX 2.1 validates."""

from __future__ import annotations

import json

from revtriage.analyze import analyze
from revtriage.report import to_json, to_markdown, to_stix_bundle, validate_bundle


def test_json_is_parseable_and_carries_the_verdict(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    payload = json.loads(to_json(triage))
    assert payload["score"]["verdict"] == triage.score.verdict
    assert payload["file"]["hashes"]["sha256"]
    assert "capabilities" in payload


def test_markdown_shows_verdict_iocs_and_gated_status(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    md = to_markdown(triage)
    assert "Verdict:" in md
    assert "Indicators of compromise" in md
    assert "Feature status" in md
    # A skipped PRO feature must be visible, never silently absent.
    assert "skipped" in md


def test_markdown_defangs_urls(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    md = to_markdown(triage)
    # In the IOC table the URL is defanged so it cannot be clicked out of a report.
    assert "hxxp://malware[.]example" in md
    ioc_section = md.split("## Indicators of compromise", 1)[1].split("## ", 1)[0]
    assert "http://malware.example" not in ioc_section


def test_stix_bundle_validates_for_every_corpus_sample(corpus):
    for name, data in corpus.items():
        triage = analyze(data, name=name)
        bundle = to_stix_bundle(triage)
        problems = validate_bundle(bundle)
        assert problems == [], f"{name}: {problems}"


def test_stix_bundle_is_deterministic(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    from datetime import datetime, timezone

    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = to_stix_bundle(triage, now=fixed)
    second = to_stix_bundle(triage, now=fixed)
    assert first == second  # content-derived ids -> identical bundles


def test_stix_has_attack_patterns_with_mitre_refs(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    bundle = to_stix_bundle(triage)
    patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert patterns
    for pattern in patterns:
        assert any(r["source_name"] == "mitre-attack" for r in pattern["external_references"])


def test_validator_catches_a_broken_bundle():
    bad = {"type": "bundle", "id": "bundle--not-a-uuid", "objects": [{"type": "indicator", "id": "x"}]}
    problems = validate_bundle(bad)
    assert problems  # the validator must actually reject malformed input
