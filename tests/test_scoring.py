"""Scoring tests, written to be killed by mutation.

Each test that targets a specific operator or threshold says so in its docstring: if you
flip that operator in `scoring.py`, the named test must go red. A pass that survives the
mutation would be theatre, so these assert exact numbers, not "greater than zero".
"""

from __future__ import annotations

import pytest

from revtriage.capabilities import attack
from revtriage.model import Match
from revtriage.scoring import (
    SCORE_MAX,
    VERDICT_BANDS,
    compute_score,
    score_graph,
    verdict_for,
)
from revtriage.capabilities.graph import build_graph


def m(rule_id: str, capability: str, weight: int, layer: str = "L0") -> Match:
    return Match(
        rule_id=rule_id,
        capability=capability,
        name=rule_id,
        weight=weight,
        techniques=(),
        evidence="synthetic",
        layer=layer,
    )


def test_empty_is_benign_zero():
    score = compute_score([])
    assert score.value == 0
    assert score.verdict == "benign"


def test_single_capability_sums_rule_weights():
    # discovery cap is 8; 3 + 3 = 6 is under it, so contribution is the raw sum.
    score = compute_score([m("disco.user", "discovery", 3), m("disco.net", "discovery", 3)])
    assert score.value == 6
    assert score.capped == []


def test_cap_is_a_minimum_not_a_maximum():
    """Kills min()->max() in score_graph: discovery is capped at 8, raw weight is 20."""
    cap = attack.CAPABILITIES["discovery"].cap
    assert cap == 8
    matches = [m(f"disco.{i}", "discovery", 10, layer=f"L{i}") for i in range(2)]  # raw 20
    # give them distinct rule ids so the distinct-rule sum really is 20
    score = compute_score(matches)
    assert score.value == cap  # 8, not 20 and not 10
    assert "discovery" in score.capped


def test_distinct_rule_weighting_ignores_duplicate_layers():
    """The same rule firing in two layers counts once — kills a per-match sum."""
    matches = [m("c2.web", "command-and-control", 6, layer="L0"),
               m("c2.web", "command-and-control", 6, layer="strings")]
    score = compute_score(matches)
    assert score.value == 6  # not 12


def test_lethal_combination_adds_its_bonus():
    """Kills dropping the edge bonus: persistence+C2 must add exactly its listed bonus."""
    bonus = next(b for (pair, b, _) in attack.LETHAL_COMBINATIONS
                 if set(pair) == {"persistence", "command-and-control"})
    base = compute_score([m("persist.run-key", "persistence", 8)]).value \
        + compute_score([m("c2.web", "command-and-control", 6)]).value
    together = compute_score([
        m("persist.run-key", "persistence", 8),
        m("c2.web", "command-and-control", 6),
    ])
    assert together.value == base + bonus
    assert any("Lethal combination" in c.label for c in together.components)


def test_score_clamps_to_100():
    """Kills removing the upper clamp."""
    matches = []
    for cap_id in attack.CAPABILITIES:
        matches.append(m(f"r.{cap_id}", cap_id, 999, layer=cap_id))
    score = compute_score(matches)
    assert score.value == SCORE_MAX == 100


@pytest.mark.parametrize(
    "value,verdict",
    [
        (0, "benign"), (9, "benign"),
        (10, "suspicious"), (29, "suspicious"),
        (30, "likely-malicious"), (59, "likely-malicious"),
        (60, "malicious"), (100, "malicious"),
    ],
)
def test_verdict_band_boundaries(value, verdict):
    """Kills >= -> > (and boundary off-by-ones) in verdict_for at every band edge."""
    assert verdict_for(value) == verdict


def test_verdict_bands_are_ordered_and_cover_zero():
    thresholds = [t for t, _ in VERDICT_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
    assert thresholds[-1] == 0  # every non-negative score maps to a verdict


def test_components_account_for_the_whole_number():
    """The printed breakdown must actually sum to the score (minus clamping)."""
    matches = [
        m("persist.run-key", "persistence", 8),
        m("c2.web", "command-and-control", 6),
        m("cred.lsass", "credential-access", 12),
        m("exfil.cloud", "exfiltration", 6),
    ]
    score = compute_score(matches)
    assert sum(c.points for c in score.components) == score.value


def test_score_graph_matches_compute_score():
    matches = [m("inject.remote-thread", "injection", 12), m("anti.vm", "anti-analysis", 8)]
    assert score_graph(build_graph(matches)).value == compute_score(matches).value
