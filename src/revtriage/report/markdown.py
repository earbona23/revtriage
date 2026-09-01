"""The human report.

Ordered the way an analyst reads: verdict first (so triage can stop early on an obvious
one), then the *why* — the scored components, the capability graph, the ATT&CK map — then
the raw material (IOCs, provenance layers, structural facts), and finally an honest
account of what did not run. The gated-features section is not an afterthought: it is the
guarantee that a PRO-only capability shows as "skipped, because…" and never as an empty
result that could be misread as "clean".
"""

from __future__ import annotations

from ..iocs import defang
from ..model import Triage

_VERDICT_MARK = {
    "malicious": "CRITICAL",
    "likely-malicious": "HIGH",
    "suspicious": "ELEVATED",
    "benign": "LOW",
}


def to_markdown(triage: Triage) -> str:
    out: list[str] = []
    w = out.append

    w(f"# revtriage report — `{triage.filename}`\n")
    _verdict_block(w, triage)
    _file_block(w, triage)
    _score_block(w, triage)
    _graph_block(w, triage)
    _attack_block(w, triage)
    _ioc_block(w, triage)
    _layer_block(w, triage)
    _facts_block(w, triage)
    _gated_block(w, triage)
    if triage.errors:
        w("## Errors\n")
        for error in triage.errors:
            w(f"- {error}")
        w("")

    w("---")
    w(f"_Generated offline by revtriage {triage.tool.get('version', '')}. "
      f"Nothing in this analysis was uploaded. {triage.tool.get('attack', '')}_")
    return "\n".join(out) + "\n"


def _verdict_block(w, triage: Triage) -> None:
    if not triage.score:
        w("> No score computed.\n")
        return
    mark = _VERDICT_MARK.get(triage.score.verdict, "")
    w(f"## Verdict: **{triage.score.verdict.upper()}**  ({mark})\n")
    w(f"**Threat score: {triage.score.value} / 100**\n")
    bar_full = triage.score.value // 5
    w("```")
    w(f"[{'#' * bar_full}{'.' * (20 - bar_full)}] {triage.score.value}/100")
    w("```\n")


def _file_block(w, triage: Triage) -> None:
    w("## File\n")
    ft = triage.file_type
    w(f"- **Type:** {ft.get('label')} (`{ft.get('kind')}`, decided by {ft.get('basis')})")
    if ft.get("dialect"):
        w(f"- **Dialect:** {ft.get('dialect')}")
    w(f"- **Size:** {triage.size:,} bytes")
    w(f"- **SHA-256:** `{triage.hashes.get('sha256', '')}`")
    w(f"- **SHA-1:** `{triage.hashes.get('sha1', '')}`")
    w(f"- **MD5:** `{triage.hashes.get('md5', '')}`")
    w("")


def _score_block(w, triage: Triage) -> None:
    if not triage.score or not triage.score.components:
        return
    w("## How the score was built\n")
    w("| Contribution | Points | Why |")
    w("|---|---:|---|")
    for component in triage.score.components:
        detail = component.detail.replace("|", "\\|")
        w(f"| {component.label} | {component.points} | {detail} |")
    w("")
    if triage.score.capped:
        w(f"> Capped capabilities (raw signal exceeded the ceiling): "
          f"{', '.join(triage.score.capped)}.\n")


def _graph_block(w, triage: Triage) -> None:
    graph = triage.tool.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return
    w("## Capability graph\n")
    w("```")
    for node in nodes:
        techniques = ", ".join(node["attack_techniques"][:6])
        w(f"[{node['title']}]  weight {node['weight']}  ({node['match_count']} match)")
        if techniques:
            w(f"    -> {techniques}")
    if edges:
        w("")
        w("lethal combinations present:")
        for edge in edges:
            w(f"    ({edge['source']}) ==+{edge['bonus']}==> ({edge['target']}) : {edge['rationale']}")
    w("```\n")


def _attack_block(w, triage: Triage) -> None:
    from ..capabilities import attack

    if not triage.techniques:
        return
    w("## MITRE ATT&CK techniques\n")
    w("| ID | Technique | Tactic |")
    w("|---|---|---|")
    for technique_id in triage.techniques:
        technique = attack.TECHNIQUES.get(technique_id)
        if technique:
            w(f"| [`{technique.id}`]({technique.url}) | {technique.name} | {technique.tactic} |")
        else:
            w(f"| `{technique_id}` | UNKNOWN — not in catalogue | — |")
    w("")


def _ioc_block(w, triage: Triage) -> None:
    if not triage.indicators:
        return
    w("## Indicators of compromise\n")
    w("_Defanged for safe copy-paste; see the JSON report for raw values._\n")
    w("| Type | Indicator | Layer | Context |")
    w("|---|---|---|---|")
    for indicator in triage.indicators:
        value = defang(indicator.value) if indicator.type in ("url", "domain", "ipv4", "email") else indicator.value
        value = value.replace("|", "\\|")
        w(f"| {indicator.type} | `{value}` | {indicator.layer} | {indicator.context} |")
    w("")


def _layer_block(w, triage: Triage) -> None:
    if len(triage.layers) <= 1:
        return
    w("## Deobfuscation layers\n")
    w("_Provenance: each layer names the technique that produced it and its parent._\n")
    w("| Layer | Depth | Technique | From | Size | Preview |")
    w("|---|---:|---|---|---:|---|")
    for layer in triage.layers:
        preview = layer.to_dict()["preview"].replace("|", "\\|")
        w(f"| {layer.id} | {layer.depth} | {layer.technique} | {layer.parent or '—'} "
          f"| {len(layer.data)} | {preview} |")
    w("")


def _facts_block(w, triage: Triage) -> None:
    if not triage.facts:
        return
    w("## Structural facts\n")
    for fact in triage.facts:
        note = f" — _{fact.note}_" if fact.note else ""
        w(f"- **{fact.key}:** `{fact.value}`{note}")
    w("")


def _gated_block(w, triage: Triage) -> None:
    if not triage.gated:
        return
    w("## Feature status (free vs PRO)\n")
    w("| Feature | Status | Detail |")
    w("|---|---|---|")
    for gated in triage.gated:
        w(f"| {gated.name} | **{gated.status}** | {gated.reason} |")
    w("")
