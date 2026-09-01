"""The threat score: one number, and a full accounting of where it came from.

A score an analyst cannot interrogate is worse than no score, because it invites the two
failure modes a triage tool exists to prevent — waving through a bad file because the
number looked low, and burning an hour on a benign one because it looked high. So every
point in the total traces to a line in `Score.components`, and the report prints them.

How the number is built
-----------------------
1. **Per-capability contribution.** Each capability present contributes the sum of its
   matched rule weights, *capped* at the ceiling in `attack.CAPABILITIES`. The cap is the
   load-bearing part: without it, a sample that trips the same behaviour twenty ways
   would outscore a genuinely more dangerous one that does three distinct things. When a
   capability is capped, the report says so — the analyst should know the raw signal was
   even stronger than the number admits.
2. **Lethal-combination bonuses.** Some pairs of capabilities mean far more together than
   apart (persistence + C2 = an implant; credential-access + exfiltration = a thief with
   a way out). Each present pair adds a bonus, listed with its rationale.
3. **Clamp to 0–100** and map to a verdict band.

Only CORE matches reach this function. Extended (PRO) matches are reported separately and
never alter the number here, which is what lets the tool promise that a PRO licence adds
detail without ever changing a free-tier verdict.

The thresholds are a triage prior, documented in docs/scoring.md, not a probability of
maliciousness. They are deliberately conservative on the low end: revtriage decides what
a human looks at first, it does not decide guilt.
"""

from __future__ import annotations

from .capabilities import attack
from .capabilities.graph import CapabilityGraph, build_graph
from .model import Match, Score, ScoreComponent

#: (inclusive lower bound, verdict). Checked high-to-low. Documented in docs/scoring.md.
VERDICT_BANDS: tuple[tuple[int, str], ...] = (
    (60, "malicious"),
    (30, "likely-malicious"),
    (10, "suspicious"),
    (0, "benign"),
)

SCORE_MIN = 0
SCORE_MAX = 100


def verdict_for(value: int) -> str:
    for threshold, verdict in VERDICT_BANDS:
        if value >= threshold:
            return verdict
    return "benign"


def compute_score(matches: list[Match]) -> Score:
    """Score a list of CORE matches. Convenience wrapper over the graph form."""
    return score_graph(build_graph(matches))


def score_graph(graph: CapabilityGraph) -> Score:
    """Score a built capability graph, recording every contribution and every cap hit."""
    components: list[ScoreComponent] = []
    capped: list[str] = []
    total = 0

    for node in graph.nodes:
        capability = attack.CAPABILITIES.get(node.capability)
        ceiling = capability.cap if capability else node.weight
        contribution = min(node.weight, ceiling)
        total += contribution

        rule_ids = sorted({m.rule_id for m in node.matches})
        detail = f"{len(node.matches)} match(es) via {', '.join(rule_ids)}"
        if node.weight > ceiling:
            capped.append(node.capability)
            detail += f"; raw weight {node.weight} capped at {ceiling}"
        components.append(
            ScoreComponent(label=node.title, points=contribution, detail=detail)
        )

    for edge in graph.edges:
        total += edge.bonus
        components.append(
            ScoreComponent(
                label=f"Lethal combination: {edge.source} + {edge.target}",
                points=edge.bonus,
                detail=edge.rationale,
            )
        )

    value = max(SCORE_MIN, min(total, SCORE_MAX))
    return Score(value=value, verdict=verdict_for(value), components=components, capped=capped)
