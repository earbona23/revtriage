"""The data the analysis passes around.

Everything is a plain dataclass with an explicit `to_dict`, because the JSON report is a
public contract: an analyst pipes it into other tools, and a field that silently changes
shape breaks them. Serialisation therefore lives next to the definition, not in the
reporter, so a new field cannot be added without deciding how it is published.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Layer:
    """One body of content the analysis can match rules against.

    Layer 0 is always the file itself. Every other layer is the output of a
    deobfuscation step, and keeps a pointer to the layer it came from. That chain is what
    lets the report say *"this URL was not in the file — it appeared after base64, then a
    single-byte XOR with 0x5A"*, which is the difference between an indicator an analyst
    can act on and one they have to re-derive by hand.
    """

    id: str
    depth: int
    technique: str
    description: str
    data: bytes
    parent: str | None = None

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "depth": self.depth,
            "technique": self.technique,
            "description": self.description,
            "parent": self.parent,
            "size": len(self.data),
            "preview": _preview(self.text),
        }


@dataclass(frozen=True)
class Indicator:
    """An IOC, with the layer it was observed in."""

    type: str
    value: str
    layer: str
    context: str = ""

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value, "layer": self.layer, "context": self.context}


@dataclass(frozen=True)
class Match:
    """A capability rule that fired."""

    rule_id: str
    capability: str
    name: str
    weight: int
    techniques: tuple[str, ...]
    evidence: str
    layer: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "capability": self.capability,
            "name": self.name,
            "weight": self.weight,
            "attack_techniques": list(self.techniques),
            "evidence": self.evidence,
            "layer": self.layer,
        }


@dataclass(frozen=True)
class Fact:
    """A structural observation about the file: a section, an import table, a macro."""

    key: str
    value: object
    note: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "note": self.note}


@dataclass
class ScoreComponent:
    label: str
    points: int
    detail: str

    def to_dict(self) -> dict:
        return {"label": self.label, "points": self.points, "detail": self.detail}


@dataclass
class Score:
    value: int
    verdict: str
    components: list[ScoreComponent] = field(default_factory=list)
    capped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "verdict": self.verdict,
            "components": [c.to_dict() for c in self.components],
            "capped_capabilities": list(self.capped),
        }


@dataclass
class GatedFeature:
    """A feature that did not run, and the honest reason why.

    A gated feature must never look like a feature that ran and found nothing. `status`
    is one of 'ok', 'skipped' or 'error'; a 'skipped' feature carries the reason and the
    report prints it. Silence here would be the worst kind of bug in a security tool:
    an empty section that reads as "all clear".
    """

    name: str
    status: str
    reason: str

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "reason": self.reason}


@dataclass
class Triage:
    """The complete result of analysing one file."""

    filename: str
    size: int
    hashes: dict
    file_type: dict
    facts: list[Fact] = field(default_factory=list)
    layers: list[Layer] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    score: Score | None = None
    gated: list[GatedFeature] = field(default_factory=list)
    tool: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def capabilities(self) -> dict[str, list[Match]]:
        """Matches grouped by capability — the nodes of the capability graph."""
        grouped: dict[str, list[Match]] = {}
        for match in self.matches:
            grouped.setdefault(match.capability, []).append(match)
        return grouped

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
            "tool": self.tool,
            "file": {
                "name": self.filename,
                "size": self.size,
                "hashes": self.hashes,
                "type": self.file_type,
            },
            "score": self.score.to_dict() if self.score else None,
            "capabilities": {
                capability: [m.to_dict() for m in matches]
                for capability, matches in sorted(self.capabilities.items())
            },
            "attack_techniques": self.techniques,
            "indicators": [i.to_dict() for i in self.indicators],
            "layers": [layer.to_dict() for layer in self.layers],
            "facts": [fact.to_dict() for fact in self.facts],
            "gated_features": [g.to_dict() for g in self.gated],
            "errors": list(self.errors),
        }


def _preview(text: str, limit: int = 220) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
