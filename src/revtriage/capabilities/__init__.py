"""The capability layer: rules turn evidence into `Match`es, the graph organises them.

`attack.py` holds the vocabulary (ATT&CK techniques and the capability taxonomy above
them). `rules.py` holds the detections — each maps a concrete pattern, imported symbol or
structural note to a capability and one or more techniques. `graph.py` folds the matches
into the capability graph the report and the scorer both consume.

The split matters: a rule never invents a technique ID, it references one from the
catalogue, and a test enforces that every reference resolves. That is what keeps the
report's ATT&CK citations trustworthy.
"""

from __future__ import annotations

from . import attack, graph, rules
from .graph import CapabilityGraph, build_graph
from .rules import CORE_RULES, EXTENDED_RULES, Rule, run_rules, validate_rules

__all__ = [
    "attack",
    "graph",
    "rules",
    "Rule",
    "CORE_RULES",
    "EXTENDED_RULES",
    "run_rules",
    "validate_rules",
    "CapabilityGraph",
    "build_graph",
]
