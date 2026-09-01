"""The capability graph: capabilities are nodes, lethal combinations are edges.

A flat list of matches answers "what did it do". The graph answers the more useful triage
question: "what does the combination *mean*". A file that only profiles the host is noise;
one that profiles the host *and* encrypts it is a ransomware pre-flight. Those pairings —
the ones that mean far more together than apart — are the `LETHAL_COMBINATIONS` in
`attack.py`, and here they become edges between the nodes that are actually present.

The graph is the shared substrate for both the report (which draws it) and the scorer
(which reads node weights and edge bonuses), so the number in the report and the picture
in the report can never disagree: they are computed from the same object.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import Match
from . import attack


@dataclass
class Node:
    capability: str
    title: str
    matches: list[Match] = field(default_factory=list)

    @property
    def weight(self) -> int:
        # Weight is summed over *distinct rules*, not raw matches. The same rule firing
        # in three layers is provenance for one behaviour, not three times the evidence —
        # and the original file and the extracted-strings pseudo-layer overlap heavily,
        # so counting per-match would silently double every string-based detection.
        best: dict[str, int] = {}
        for match in self.matches:
            best[match.rule_id] = match.weight
        return sum(best.values())

    @property
    def techniques(self) -> list[str]:
        seen: list[str] = []
        for match in self.matches:
            for technique in match.techniques:
                if technique not in seen:
                    seen.append(technique)
        return sorted(seen)

    def to_dict(self) -> dict:
        return {
            "capability": self.capability,
            "title": self.title,
            "match_count": len(self.matches),
            "weight": self.weight,
            "attack_techniques": self.techniques,
            "rules": sorted({m.rule_id for m in self.matches}),
        }


@dataclass
class Edge:
    source: str
    target: str
    bonus: int
    rationale: str

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "bonus": self.bonus,
            "rationale": self.rationale,
        }


@dataclass
class CapabilityGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    @property
    def capability_ids(self) -> set[str]:
        return {node.capability for node in self.nodes}

    def to_dict(self) -> dict:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


def build_graph(matches: list[Match]) -> CapabilityGraph:
    """Fold matches into nodes, then connect the lethal combinations that are present."""
    grouped: dict[str, Node] = {}
    for match in matches:
        node = grouped.get(match.capability)
        if node is None:
            capability = attack.CAPABILITIES.get(match.capability)
            title = capability.title if capability else match.capability
            node = Node(capability=match.capability, title=title)
            grouped[match.capability] = node
        node.matches.append(match)

    present = set(grouped)
    edges: list[Edge] = []
    for (first, second), bonus, rationale in attack.LETHAL_COMBINATIONS:
        if first in present and second in present:
            edges.append(Edge(source=first, target=second, bonus=bonus, rationale=rationale))

    # Stable ordering: nodes by descending weight then id, edges by descending bonus.
    nodes = sorted(grouped.values(), key=lambda n: (-n.weight, n.capability))
    edges.sort(key=lambda e: (-e.bonus, e.source, e.target))
    return CapabilityGraph(nodes=nodes, edges=edges)
