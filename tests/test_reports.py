"""Report tests: JSON round-trips, Markdown shows the honest bits, STIX 2.1 validates."""

from __future__ import annotations

import json

import pytest

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


def test_validator_names_the_defect_it_found(valid_bundle):
    """Each check is asserted by the message it produces, not by the list being non-empty.

    `assert problems` is satisfied by ANY complaint, so a bundle with two defects keeps the
    test green after one of the two checks is deleted. Every invariant below is broken on
    its own, in an otherwise valid bundle, and matched by name.
    """
    import copy

    def problems_after(mutate) -> list[str]:
        bundle = copy.deepcopy(valid_bundle)
        mutate(bundle)
        return validate_bundle(bundle)

    def sets(field, value):
        def apply(bundle):
            bundle["objects"][0][field] = value
        return apply

    assert validate_bundle(copy.deepcopy(valid_bundle)) == []

    malformed = problems_after(sets("id", "not-a-stix-id"))
    assert any("malformed id" in p for p in malformed), malformed

    # A well-formed id that belongs to the wrong type: the objects[0] here is an
    # `identity`, so an `indicator--` id must be caught by the prefix check alone.
    prefix = problems_after(sets("id", "indicator--00000000-0000-4000-8000-000000000000"))
    assert any("prefix does not match type" in p for p in prefix), prefix

    def break_bundle_type(bundle):
        bundle["type"] = "collection"

    assert any("type is not 'bundle'" in p for p in problems_after(break_bundle_type))

    def empty_objects(bundle):
        bundle["objects"] = []

    assert any("non-empty list" in p for p in problems_after(empty_objects))


@pytest.fixture
def valid_bundle(corpus):
    """A real, valid bundle — the baseline the per-defect assertions mutate."""
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    bundle = to_stix_bundle(triage)
    assert validate_bundle(bundle) == []
    return bundle
