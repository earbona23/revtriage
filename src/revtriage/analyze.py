"""The pipeline: bytes in, a `Triage` out. Pure parsing and pattern matching, no execution.

The order is deliberate and each stage feeds the next:

    identify → extract structure → strings → deobfuscate → rules → graph → score → IOCs

Structure extraction runs first because it produces the *bodies* (macro source, a script
inside an archive) that deobfuscation then treats as additional layers. Rules run over
every text layer — original, embedded and decoded — so a detection can fire on a command
that only exists after three rounds of decoding, and the `Match` records which layer.

The free tier produces everything that drives the verdict. The PRO tier adds extended
rules whose matches are *appended after the score is computed*, which is what makes the
"additive, never changes a core verdict" guarantee a fact of control flow rather than a
promise: `triage.score` is frozen before an extended match can exist.
"""

from __future__ import annotations

from . import __version__, iocs
from .capabilities import attack, build_graph, run_rules
from .capabilities.rules import CORE_RULES, EXTENDED_RULES
from .deobfuscate import deobfuscate
from .extract import extract_strings, extract_structure
from .identify import identify
from .license import LicenseResult, gate
from .license.verify import LicenseResult as _LR
from .model import GatedFeature, Triage
from .scoring import compute_score
from .util import file_hashes

FEATURE_EXTENDED_RULES = "extended-rules"
FEATURE_HTML_REPORT = "html-report"
FEATURE_SANDBOX = "sandbox-detonation"


def analyze(
    data: bytes,
    name: str | None = None,
    license_result: LicenseResult | None = None,
    strings_min: int = 5,
) -> Triage:
    """Analyse `data` and return a complete `Triage`. Never executes the sample."""
    license_result = license_result or _LR(False, "no licence supplied — free tier")
    filename = name or "input"
    errors: list[str] = []

    ident = identify(data, name_hint=name)
    facts, imports, structure_notes, bodies = extract_structure(data, ident)
    strings = extract_strings(data, minimum=strings_min)

    layers, deob_notes = deobfuscate(data, extra_bodies=bodies)

    # The search space for rules and IOCs: every decoded layer, plus a synthetic layer
    # holding the extracted strings. The strings layer is what surfaces UTF-16 API names
    # and wide-char URLs that a raw decode of a binary's bytes would miss.
    texts: list[tuple[str, str]] = [(layer.id, layer.text) for layer in layers]
    if strings:
        texts.append(("strings", "\n".join(strings)))

    core_matches = run_rules(CORE_RULES, texts, imports, structure_notes)
    graph = build_graph(core_matches)
    score = compute_score(core_matches)  # frozen here: PRO detail below cannot touch it.

    indicators = iocs.extract(texts)

    # -- gated (PRO) features --------------------------------------------------------
    gated: list[GatedFeature] = []

    extended_gate = gate(FEATURE_EXTENDED_RULES, license_result)
    matches = list(core_matches)
    if extended_gate.status == "ok":
        extended_matches = run_rules(EXTENDED_RULES, texts, imports, structure_notes)
        matches.extend(extended_matches)
        extended_gate = GatedFeature(
            FEATURE_EXTENDED_RULES, "ok",
            f"{len(extended_matches)} extended finding(s) added (additive; the score is unchanged)",
        )
    gated.append(extended_gate)

    gated.append(gate(FEATURE_HTML_REPORT, license_result))

    # Sandbox detonation is a design document, not an implementation. It is always
    # skipped, and says why, so it can never read as "ran and found nothing" — revtriage
    # is 100% offline and never executes a sample, by design.
    gated.append(
        GatedFeature(
            FEATURE_SANDBOX, "skipped",
            "design only (docs/sandbox-design.md); revtriage never executes samples",
        )
    )

    notes = sorted(set(structure_notes) | set(deob_notes))
    if notes:
        facts = list(facts) + [_note_fact(notes)]

    return Triage(
        filename=filename,
        size=len(data),
        hashes=file_hashes(data),
        file_type={
            "kind": ident.kind,
            "label": ident.label,
            "evidence": ident.evidence,
            "basis": ident.basis,
            "dialect": ident.dialect,
            "details": _jsonable(ident.details),
        },
        facts=facts,
        layers=layers,
        indicators=indicators,
        matches=matches,
        score=score,
        gated=gated,
        tool={
            "name": "revtriage",
            "version": __version__,
            "offline": True,
            "attack": attack.ATTACK_VERSION_NOTE,
            "license_tier": license_result.tier if license_result.valid else "free",
            "license_subject": license_result.subject if license_result.valid else None,
            "graph": graph.to_dict(),
        },
        errors=errors,
    )


def _note_fact(notes: list[str]):
    from .model import Fact

    return Fact("structural.notes", notes, "structural tags emitted by extractors and the deobfuscator")


def _jsonable(details: dict) -> dict:
    """Trim the bulky, non-scalar corners of an Identification's details for the report."""
    out: dict = {}
    for key, value in details.items():
        if key == "entries" and isinstance(value, list):
            out["entry_count"] = len(value)
            out["entries_sample"] = value[:20]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
    return out
